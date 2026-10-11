"""codecs — bốn phép giải mã biểu diễn dữ liệu (REQ-21–24, ADR-20, ADR-21).

Tệp DUY NHẤT của bài 2 import module giải mã của thư viện chuẩn — gom chỗ cần
giải thích khi vấn đáp về một nơi (NFR-14). Vai trò chia theo ADR-20 phương án B:
thư viện **biến đổi** byte, phần tự viết là **bộ phân loại trạng thái** — kiểm giới
hạn, tự dò dấu hiệu sai định dạng, rồi gọi hàm stdlib, rồi trả `DecodedValue`.
Không tự viết bộ giải mã nào (C-22) và cũng không trùng việc với thư viện.

Mỗi hàm trả một `DecodedValue` (§5.1): `{value, rule, status, reasons}`. `rule`
để None ở đây — Decoder (stage) mới biết mình đang áp F1 hay F2 và nối "F1+F4",
nên nó gán `rule`; codecs chỉ lo biến đổi + phân loại. Không hàm nào ném: lỗi dự
kiến là dữ liệu, trả qua `status`/`reasons` (ADR-4 của bài 1).

Lưu ý tên tệp: đây là `idps.process.codecs`, KHÔNG che `codecs` của thư viện
chuẩn — Python 3 dùng absolute import nên `import codecs` ở nơi khác vẫn ra stdlib.
"""
import html
import html.entities
import re
import urllib.parse

_HEX = set("0123456789abcdefABCDEF")

# Một tham chiếu entity: &#NNN · &#xHH (số) · &name (chữ), tuỳ chọn kết thúc `;`.
_ENTITY_REF = re.compile(r"&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*)(;?)")
# Bảng tra entity HTML5 của thư viện chuẩn: khoá có `;` ('lt;') và khoá KHÔNG `;`
# ('lt') — tập không `;` chính là các entity hợp lệ thiếu `;` của HTML5. Dùng để
# DÒ (html.unescape mới là chỗ giải mã — ADR-27).
_HTML5 = html.entities.html5


def decoded(value, rule, status, reasons=None):
    """Dựng một `DecodedValue` — bốn khoá đúng thứ tự §5.1, `reasons` là list RIÊNG.

    Tạo list mới mỗi lần để hai kết quả không chia nhau một list `reasons` (I-1).
    """
    return {
        "value": value,
        "rule": rule,
        "status": status,
        "reasons": list(reasons) if reasons else [],
    }


def to_text(data):
    """bytes → text theo luật thay thế cố định ADR-21. Không ném (REQ-24.2).

    Hai lần decode là có chủ ý: lần đầu **strict** để BIẾT chỗ byte lỗi đầu tiên
    (`e.start`, `data[e.start]`), lần sau `errors="replace"` để CÓ một giá trị
    (mỗi byte lỗi thành U+FFFD). Dùng `replace` chứ không `surrogateescape`
    (ADR-21): lone surrogate làm `json.dumps` sinh chuỗi không phải Unicode hợp
    lệ, phá NFR-12. Bytes gốc vẫn ở `*_b64` của bài 1 nên I-4 không cần chuỗi này
    giải mã ngược.
    """
    try:
        return decoded(data.decode("utf-8"), None, "ok")
    except UnicodeDecodeError as exc:
        bad = data[exc.start]
        reason = f"utf8_invalid_byte_at={exc.start} value=0x{bad:02X}"
        return decoded(data.decode("utf-8", errors="replace"), None, "partial", [reason])


def _first_invalid_percent(value):
    """Vị trí dấu `%` đầu tiên KHÔNG theo sau bởi hai chữ số hex, hoặc None.

    Dò trên chuỗi NGUỒN vì `unquote_to_bytes` im lặng giữ nguyên đoạn sai (đo:
    `"100%25 vs %ZZ %2"` → `"100% vs %ZZ %2"`, không báo gì — ADR-20). Báo vị trí
    đầu tiên theo đúng lối "byte lỗi đầu tiên" của ADR-21, đủ để ghi `partial`.
    """
    n = len(value)
    i = value.find("%")
    while i != -1:
        if i + 2 >= n or value[i + 1] not in _HEX or value[i + 2] not in _HEX:
            return i
        i = value.find("%", i + 3)
    return None


def _over_limit(value, limit):
    """DecodedValue cho ca bỏ phép decode vì vượt `max_decode_bytes` (REQ-37.4).

    Bỏ hẳn phép decode (value = null), reason nêu giới hạn đã áp dụng. `partial`
    vì kết quả không trọn vẹn — không `invalid` (dữ liệu không sai), cũng không
    `not_applicable` (phép decode LẼ RA áp dụng được, chỉ bị chặn vì tài nguyên).
    """
    return decoded(None, None, "partial", [f"input_over_max_decode_bytes={limit}"])


def percent_decode(value, limit):
    """Percent-decode MỘT lần (F1), rồi đưa bytes về text theo ADR-21.

    `%2527` → `%27` chứ không `'` (I-14): `unquote_to_bytes` giải `%25`→`%` rồi
    dừng, không đệ quy. Dùng bản ra **bytes** để luật UTF-8 (ADR-21) chạy đúng một
    lần ở `to_text`, thay vì bị `unquote` làm trước một cách âm thầm. `%` lạc →
    `partial` (REQ-21.6), đoạn đó giữ nguyên trong kết quả.
    """
    if len(value) > limit:
        return _over_limit(value, limit)
    reasons = []
    bad = _first_invalid_percent(value)
    if bad is not None:
        reasons.append(f"invalid_percent_escape_at={bad}")
    text = to_text(urllib.parse.unquote_to_bytes(value))
    reasons += text["reasons"]
    status = "partial" if (bad is not None or text["status"] == "partial") else "ok"
    return decoded(text["value"], None, status, reasons)


def form_decode(value, limit):
    """Tách cặp `application/x-www-form-urlencoded` (F2/F3): `&` ngăn cặp, `=`
    ngăn tên/giá trị, `+` → dấu cách; percent-decode từng phần (parse_qsl lo).

    `keep_blank_values=True` giữ cặp rỗng (`c=`, `d`) làm bằng chứng — mặc định
    bỏ chúng. KHÔNG `strict_parsing=True` vì nó *ném* `ValueError` trên query
    hỏng, trong khi REQ-21.6 đòi `partial` + giữ phần đọc được. Tự dò `%` lạc để
    ghi `partial` (parse_qsl không báo). Trả list cặp `[tên, giá trị]` — kiểu JSON.
    """
    if len(value) > limit:
        return _over_limit(value, limit)
    reasons = []
    bad = _first_invalid_percent(value)
    if bad is not None:
        reasons.append(f"invalid_percent_escape_at={bad}")
    pairs = urllib.parse.parse_qsl(value, keep_blank_values=True)
    status = "partial" if bad is not None else "ok"
    return decoded([[name, val] for name, val in pairs], None, status, reasons)


def _has_known_entity_prefix(body):
    """body (chữ, không `;`) có tiền tố nào là entity hợp lệ KHÔNG `;` của HTML5?

    Mô phỏng ở mức DÒ luật khớp dài nhất của HTML5 (`&ltscript` khớp `&lt`): nếu
    có thì html.unescape SẼ giải mã đoạn đó mà thiếu `;` -> ca bất thường REQ-22.6.
    """
    return any(body[:k] in _HTML5 for k in range(len(body), 0, -1))


def entity_decode(value):
    """Giải HTML entity MỘT lần bằng html.unescape (F4/F5), tự dò ca bất thường.

    `&amp;lt;` → `&lt;` chứ không `<` (I-14, REQ-22.4): html.unescape chạy một pass,
    không giải lại kết quả. Entity thiếu `;` mà khớp luật HTML5 vẫn được giải
    (REQ-22.6, ADR-27) — IDS phải thấy dữ liệu ở dạng trình duyệt thấy, nếu không
    `&ltscript&gt` qua mặt luật phát hiện. Entity tên lạ giữ nguyên nguyên văn
    (REQ-22.5). Hai ca bất thường → `partial` kèm lý do; giá trị gốc do nơi gọi
    giữ (REQ-22.2). Không ném.

    Chỉ đánh dấu `partial` khi có DẤU HIỆU entity (có `;`, hoặc thiếu `;` nhưng
    khớp bảng tra). `&` trần trong text thường ("AT&T") KHÔNG bị đánh dấu — tránh
    cảnh báo sai tràn lan, trong khi vẫn giữ chiều "thà sai hơn sót" của ADR-27.
    """
    reasons = []
    for match in _ENTITY_REF.finditer(value):
        body, semicolon = match.group(1), match.group(2)
        numeric = body.startswith("#")
        if semicolon:
            if numeric or (body + ";") in _HTML5:
                continue                                 # &#60; / &lt; — hợp lệ
            reasons.append(f"unknown_entity_at={match.start()}")        # REQ-22.5
        elif numeric or _has_known_entity_prefix(body):
            reasons.append(f"entity_without_semicolon_at={match.start()}")  # REQ-22.6
    status = "partial" if reasons else "ok"
    return decoded(html.unescape(value), None, status, reasons)
