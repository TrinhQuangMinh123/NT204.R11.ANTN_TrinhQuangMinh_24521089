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
import base64
import binascii
import email
import email.policy
import html
import html.entities
import quopri
import re
import string
import urllib.parse

from ..core.event import b64

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
    # parse_qsl decode UTF-8 với errors="replace" một cách IM LẶNG: giá trị trả về
    # có U+FFFD mà không có lý do nào. Dò lại trên BYTES nguồn để luật ADR-21 (vị
    # trí + giá trị byte lỗi đầu tiên) áp cho F2/F3 y như F1 — nếu không, cùng một
    # query `?q=%FF` sẽ ra `partial` ở `decode.uri` nhưng `ok` ở `decode.query`.
    text = to_text(urllib.parse.unquote_to_bytes(value.replace("+", " ")))
    reasons += text["reasons"]
    status = "partial" if (bad is not None or text["status"] == "partial") else "ok"
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


# --- tổng hợp trạng thái (§5.1) — dùng chung cho mime_decode và Decoder -----

# Thứ tự nghiêm trọng: cái nói "dữ liệu sai" thắng cái nói "phạm vi hỗ trợ", cái
# "chưa làm gì" xếp cuối. Mục đứng trước = nghiêm trọng hơn.
SEVERITY = (
    "invalid", "unsupported", "unknown_encoding", "partial",
    "deferred_to_flow", "not_encoded", "ok", "not_applicable",
)


def aggregate_status(statuses):
    """Trạng thái nghiêm trọng nhất trong danh sách; rỗng → `not_applicable`."""
    if not statuses:
        return "not_applicable"
    return min(statuses, key=SEVERITY.index)


# --- Base64 và Quoted-Printable (F6/F8) — trả BYTES đã giải mã --------------
# Hai hàm này là primitive nội bộ: value là bytes (không phải str/JSON). mime_decode
# đưa bytes đó qua to_text (ra `text`) và b64 (ra `bytes_b64`) để thành JSON.

_B64_ALPHABET = set((string.ascii_letters + string.digits + "+/=").encode("ascii"))
_HEX_BYTES = set(b"0123456789abcdefABCDEF")


def _valid_b64_prefix(data):
    """Tiền tố Base64 hợp lệ, căn bội số 4 — để giữ phần giải mã được (REQ-23.7)."""
    n = 0
    for byte in data:
        if byte in _B64_ALPHABET:
            n += 1
        else:
            break
    return data[: n - (n % 4)]


def base64_decode(data, limit):
    """Giải Base64 (F6/F8) → bytes. `validate=True` SAU khi tự bỏ khoảng trắng.

    `validate=True` coi cả `\\r\\n` là ký tự sai, mà body MIME thật luôn gập dòng
    → phải bỏ khoảng trắng trước (đo: `"SGVs\\r\\nbG8="` → `b"Hello"`). KHÔNG dùng
    `validate=False` cho cả cụm vì nó *im lặng* bỏ ký tự lạ (`"SGVs*bG8="` → `b"Hello"`),
    tức payload cố tình nhiễu vẫn ra `ok`. Sai → `invalid`, giữ phần giải mã được
    từ tiền tố hợp lệ (REQ-23.7).
    """
    if len(data) > limit:
        return _over_limit(data, limit)
    stripped = b"".join(data.split())
    try:
        return decoded(base64.b64decode(stripped, validate=True), None, "ok")
    except binascii.Error as exc:
        try:
            salvaged = base64.b64decode(_valid_b64_prefix(stripped), validate=False)
        except binascii.Error:
            salvaged = b""
        return decoded(salvaged, None, "invalid", [f"base64_invalid: {exc}"])


def _first_invalid_qp(data):
    """Vị trí `=` đầu tiên KHÔNG phải `=XX` (hex) cũng không phải soft line break."""
    i = data.find(b"=")
    n = len(data)
    while i != -1:
        if i + 1 == n or data[i + 1] in (0x0D, 0x0A):
            pass                                       # '=' cuối chuỗi / '=\r' / '=\n'
        elif i + 2 < n and data[i + 1] in _HEX_BYTES and data[i + 2] in _HEX_BYTES:
            pass                                       # '=XX' hợp lệ
        else:
            return i
        i = data.find(b"=", i + 1)
    return None


def qp_decode(data, limit):
    """Giải Quoted-Printable (F6/F8) → bytes. `quopri` KHÔNG bao giờ báo lỗi:
    `=ZZ` giữ nguyên, `=` cuối bị bỏ. Nên tự quét `=` không theo sau hai chữ số
    hex (và không phải soft line break) → `invalid` + vị trí (REQ-23.7)."""
    if len(data) > limit:
        return _over_limit(data, limit)
    bad = _first_invalid_qp(data)
    status = "ok"
    reasons = []
    if bad is not None:
        status = "invalid"
        reasons.append(f"invalid_qp_escape_at={bad}")
    return decoded(quopri.decodestring(data), None, status, reasons)


# --- Bóc tách MIME (F6/F8) --------------------------------------------------

_NOT_ENCODED = {"7bit", "8bit", "binary"}
# Token của RFC 2045: chữ/số và một số dấu, KHÔNG có khoảng trắng hay CTL.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.0-9A-Z^_`a-z{|}~]+$")


def _classify_cte(raw_cte):
    """Phân loại `Content-Transfer-Encoding` → (kind, verbatim).

    kind ∈ base64 · qp · not_encoded · unsupported · unknown. Phân biệt
    `unsupported` (token đọc được, chưa cài — vd `x-uuencode`) với
    `unknown_encoding` (giá trị không phải token đọc được: rỗng, khoảng trắng,
    ký tự lạ) theo §5.1 — một IDS phải phân biệt "ta thiếu tính năng" với "thư
    hỏng/cố tình nhiễu".
    """
    if raw_cte is None:
        return "not_encoded", None                     # vắng CTE = 7bit (RFC 2045)
    token = raw_cte.strip().lower()
    if not token or not _TOKEN_RE.match(raw_cte.strip()):
        return "unknown", raw_cte
    if token == "base64":
        return "base64", raw_cte
    if token == "quoted-printable":
        return "qp", raw_cte
    if token in _NOT_ENCODED:
        return "not_encoded", raw_cte
    return "unsupported", raw_cte


def _leaf_parts(msg):
    """Các phần LÁ của thư (không phải container multipart). Thư đơn → chính nó."""
    return [part for part in msg.walk() if not part.is_multipart()]


def _decode_part(index, part, limit):
    """Một phần lá → mục của `parts[]` (§5.2): index, content_type, encoding,
    text, bytes_b64 (bytes GỐC — REQ-23.8), status, reasons."""
    kind, encoding = _classify_cte(part.get("Content-Transfer-Encoding"))
    payload = part.get_payload(decode=False)
    # latin-1 là song ánh byte 0..255 -> lấy lại đúng bytes mã hoá gốc của phần.
    encoded = payload.encode("latin-1", "replace") if isinstance(payload, str) else b""
    reasons = []
    if kind == "base64":
        dv = base64_decode(encoded, limit)
        body, status, reasons = dv["value"], dv["status"], dv["reasons"]
    elif kind == "qp":
        dv = qp_decode(encoded, limit)
        body, status, reasons = dv["value"], dv["status"], dv["reasons"]
    elif kind == "not_encoded":
        body, status = encoded, "not_encoded"
    elif kind == "unsupported":
        body, status = encoded, "unsupported"
        reasons = [f"unsupported_encoding={encoding}"]
    else:  # unknown
        body, status = encoded, "unknown_encoding"
        reasons = ["unknown_encoding"]
    text_dv = to_text(body if body is not None else b"")
    status = aggregate_status([status, text_dv["status"]])
    return {
        "index": index,
        "content_type": part.get_content_type(),
        "encoding": encoding,
        "text": text_dv["value"],
        "bytes_b64": b64(encoded),
        "status": status,
        "reasons": reasons + text_dv["reasons"],
    }


def mime_decode(data, limit):
    """Bóc tách MIME rồi giải Base64/QP theo từng phần (F6) → DecodedValue `mime`.

    `email.message_from_bytes(policy=compat32)` KHÔNG ném với thư hỏng, ghi khuyết
    điểm vào `.defects`. Thiếu dòng trống ngăn header/body → MissingHeaderBody
    SeparatorDefect → `deferred_to_flow`: không đoán encoding ở mức packet, để bước
    giải mã mức flow (REQ-40) lo (REQ-23.5). `.walk()` cho cả thư nhiều phần.
    """
    if len(data) > limit:
        return _over_limit(data, limit)
    msg = email.message_from_bytes(data, policy=email.policy.compat32)
    defects = [type(d).__name__ for d in msg.defects]
    parts = []
    for index, part in enumerate(_leaf_parts(msg)):
        parts.append(_decode_part(index, part, limit))
        defects += [type(d).__name__ for d in part.defects]

    reasons = []
    if "MissingHeaderBodySeparatorDefect" in defects:
        status = "deferred_to_flow"
        reasons.append("missing_header_body_separator")
    else:
        status = aggregate_status([p["status"] for p in parts])
    mime_obj = {
        "headers": [[name, value] for name, value in msg.items()],
        "encoding": msg.get("Content-Transfer-Encoding"),
        "parts": parts,
        "defects": list(dict.fromkeys(defects)),       # bỏ trùng, giữ thứ tự
    }
    return decoded(mime_obj, "F6", status, reasons)
