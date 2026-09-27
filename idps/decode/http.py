"""Tầng ứng dụng: parser HTTP/1.x (REQ-7.1-7.5, Phụ lục A.5, I-4).

Khác hẳn ba parser dưới nó: header IPv4/TCP/UDP là các trường NHỊ PHÂN ở vị trí
cố định, đọc bằng struct là xong. HTTP/1.x là giao thức VĂN BẢN có độ dài thay
đổi, nên chỗ kết thúc của mỗi phần không nằm ở một con số mà nằm ở một DẤU PHÂN
CÁCH phải đi tìm:

    request line  CRLF  header CRLF  header CRLF  CRLF  body
    ^-- dấu cách   ^------ dấu ":" ------^         ^-- dòng trống

Hệ quả: mọi lỗi của parser này là lỗi "tìm dấu phân cách ở đâu", và đó chính là
chỗ các kỹ thuật request smuggling sống. Vì vậy parser CỐ TÌNH nghiêm ngặt:

  * Chỉ chấp nhận CRLF, không chấp nhận LF trần. RFC 9112 §2.2 cho phép bên
    NHẬN dễ tính với LF, nhưng một IDS không phải bên nhận: nếu ta dễ tính theo
    một cách còn server dễ tính theo cách khác thì hai bên chia dòng khác nhau —
    đúng điều kiện của một cuộc tấn công desync. LF trần -> coi là chưa hoàn
    chỉnh (REQ-7.4), event vẫn nói rõ đây là HTTP.
  * Tên header giữ NGUYÊN VĂN, chỉ giá trị mới bị cắt khoảng trắng hai đầu.
    RFC 9112 §5 nói giá trị nằm giữa phần OWS tuỳ chọn (OWS không phải dữ liệu),
    còn tên thì luật phát hiện so sánh nguyên văn — một tên như "Content-Length "
    (có dấu cách) CHÍNH LÀ tín hiệu tấn công, cắt đi là xoá mất bằng chứng.
  * Gặp một dòng header sai cú pháp thì DỪNG, giữ các header đứng trước. Đọc
    tiếp sau điểm sai nghĩa là tự đoán bên kia hiểu thế nào (§4.2).

`body_len` là số byte body CÓ TRONG PACKET, không phải `Content-Length` khai
trong header (REQ-7.2 "hoặc phần body có trong packet"). Hai con số này lệch
nhau là chuyện bình thường (body trải trên nhiều segment) và cũng là một tín
hiệu đáng nghi — nên event ghi cả hai chỗ riêng: con số thật ở `body_len`, con
số bên gửi khai nằm trong `headers`.
"""
from ..core.event import b64
from .common import ParseResult

CRLF = b"\r\n"
HEADER_END = CRLF + CRLF        # dòng trống ngăn phần header với body
RESPONSE_PREFIX = b"HTTP/1."    # status line mở đầu bằng version
VERSION_PREFIX = "HTTP/1."
STATUS_CODE_LEN = 3             # RFC 9112 §4: status code đúng 3 chữ số
OWS = " \t"                     # optional whitespace (RFC 9110 §5.6.3)
DIGITS = "0123456789"

# Đúng 10 khoá của Phụ lục A.5 / design §5.4, LUÔN có mặt đủ và đúng thứ tự:
# khoá không áp dụng để null (vd `method` của một response). Nhờ vậy module bài
# sau đọc app["method"] được mà không cần .get() (I-2).
APP_FIELDS = ("kind", "method", "uri", "version", "status_code", "reason",
              "headers", "body_len", "body_b64", "incomplete")


def _new_fields(kind: str) -> dict:
    """Khung `app` đủ khoá — các bước sau chỉ ĐIỀN, không THÊM khoá."""
    return {
        "kind": kind,
        "method": None,
        "uri": None,
        "version": None,
        "status_code": None,
        "reason": None,
        "headers": [],
        "body_len": 0,
        "body_b64": "",
        "incomplete": False,
    }


def _split_header_and_body(payload: bytes):
    """payload -> (khối header, body, incomplete).

    Trả về khối header chỉ gồm các DÒNG ĐÃ KẾT THÚC. Lý do: khi chưa thấy dòng
    trống, dòng cuối cùng trong buffer có thể đang bị cắt giữa — "Content-Length:
    1" có thể là phần đầu của "Content-Length: 1024". Lấy nó vào sẽ ghi một giá
    trị sai mà không có lỗi nào báo, nên nó bị bỏ (REQ-7.4 "các header ĐẦY ĐỦ đã
    có"). Cắt theo dấu phân cách chứ không theo con số, nên bước này không có
    phép chỉ số nào ra ngoài phạm vi.
    """
    end = payload.find(HEADER_END)
    if end != -1:
        # +4 để nhảy qua chính dòng trống; body có thể rỗng (GET) hoặc chứa lại
        # chuỗi CRLFCRLF (body nhị phân) — find() lấy lần xuất hiện ĐẦU nên
        # ranh giới vẫn đúng.
        return payload[:end], payload[end + len(HEADER_END):], False

    # REQ-7.4: chưa thấy dòng trống -> header còn nằm ở segment sau. Không có
    # body nào chắc chắn ở đây, vì byte cuối buffer vẫn thuộc phần header.
    last = payload.rfind(CRLF)
    if last == -1:
        return b"", b"", True         # chưa trọn một dòng nào
    return payload[:last], b"", True


def _decode_line(raw: bytes) -> str:
    """bytes -> str ASCII nghiêm ngặt. UnicodeDecodeError -> người gọi bắt.

    Nghiêm ngặt chứ không errors="replace": REQ-7.5 đòi GHI LỖI decode, mà
    "replace" thì không có lỗi nào để ghi — nó đổi byte lạ thành U+FFFD rồi đi
    tiếp, và chuỗi ghi vào event không còn là thứ có trên dây (mất I-4).
    Byte > 0x7F trong phần header là bất thường: RFC 9110 §5.5 chỉ cho US-ASCII,
    còn obs-text là phần bỏ đi và thường là cách nhồi dữ liệu qua bộ lọc.
    """
    return raw.decode("ascii")


def _parse_request_line(line: str, fields: dict) -> str | None:
    """"GET /a HTTP/1.1" -> method, uri, version. Trả lý do lỗi hoặc None.

    Tách bằng split(" ") KHÔNG giới hạn số lần, rồi đòi đúng 3 phần — chứ không
    dùng split(" ", 2) như ở status line. Vì với request, dấu cách thứ ba là
    dấu hiệu bất thường: request-target không được chứa dấu cách (RFC 9112 §3.2),
    "GET /a b HTTP/1.1" là ca kinh điển để làm proxy và server chia dòng khác
    nhau. split(" ", 2) sẽ âm thầm nhận version = "b HTTP/1.1".
    """
    parts = line.split(" ")
    # Giữ method trước khi kiểm: đây là trường luật phát hiện cần nhất, và
    # detector đã bảo đảm payload mở đầu bằng "<METHOD> " (REQ-14.1).
    fields["method"] = parts[0]
    if len(parts) != 3:
        return (f"http request line has {len(parts)} space-separated parts, "
                f"expected 3 (method, target, version)")
    fields["uri"], fields["version"] = parts[1], parts[2]
    if not parts[2].startswith(VERSION_PREFIX):
        return f"http request declares version {parts[2]!r}, not HTTP/1.x"
    return None


def _parse_status_line(line: str, fields: dict) -> str | None:
    """"HTTP/1.1 200 OK" -> version, status_code (int), reason.

    Ở đây split(" ", 2) là ĐÚNG, ngược với request line: reason phrase được
    phép chứa dấu cách ("404 Not Found"), nên mọi thứ sau số là reason.
    """
    parts = line.split(" ", 2)
    fields["version"] = parts[0]
    if len(parts) < 2:
        return f"http status line {line!r} has no status code"
    # RFC 9112 §4 cho phép reason phrase rỗng; thiếu hẳn cũng không đáng báo lỗi
    # vì không có dữ liệu nào bị hiểu sai. "" khác null: null = đây là request.
    fields["reason"] = parts[2] if len(parts) == 3 else ""

    code = parts[1]
    # Không dùng code.isdigit(): nó trả True cho chữ số của các hệ chữ khác
    # (vd "٢٠٠" tiếng Ả Rập) và cho cả "²", nên int() sau đó có thể ra một con
    # số không ai gửi. So với tập ký tự tường minh thì không có ngoại lệ ngầm.
    if len(code) != STATUS_CODE_LEN or any(ch not in DIGITS for ch in code):
        return (f"http status code {code!r} is not "
                f"{STATUS_CODE_LEN} decimal digits")
    # int chứ không phải str (REQ-7.3): luật phát hiện sau này cần so sánh
    # khoảng (4xx, 5xx), mà so sánh chuỗi thì "99" > "500".
    fields["status_code"] = int(code)
    return None


def _parse_headers(raw_lines: list, fields: dict) -> str | None:
    """Các dòng sau start line -> [[tên, giá trị], ...], giữ thứ tự và trùng lặp.

    List cặp chứ không dict: HTTP cho phép một tên xuất hiện nhiều lần, và hai
    dòng Content-Length khác nhau là một tín hiệu tấn công — dict sẽ ghi đè và
    xoá đúng bằng chứng đó. Thứ tự cũng được giữ vì nó là dữ liệu nhận dạng
    client (fingerprint).
    """
    for number, raw in enumerate(raw_lines, start=2):   # dòng 1 là start line
        try:
            line = _decode_line(raw)
        except UnicodeDecodeError as exc:
            # REQ-7.5. Ghi số dòng và vị trí byte để soi lại bằng xxd được ngay.
            return (f"http header line {number} cannot decode as ascii: "
                    f"byte 0x{raw[exc.start]:02x} at offset {exc.start}")

        name, separator, value = line.partition(":")
        if not separator:
            # Không có dấu ":" -> hoặc là obs-fold (dòng nối, đã bỏ từ RFC 7230),
            # hoặc là rác. Cả hai đều là chỗ hai bên nhận có thể hiểu khác nhau.
            return f"http header line {number} has no colon: {line!r}"
        if not name or name.strip(OWS) != name:
            # Tên rỗng, hoặc có khoảng trắng quanh dấu ":" — RFC 9112 §5.1 buộc
            # TỪ CHỐI, vì proxy cắt khoảng trắng còn server thì không (hoặc
            # ngược lại) là cách tạo ra hai cách đọc cho cùng một message.
            return (f"http header line {number} has an invalid field name "
                    f"{name!r} (empty, folded, or padded with whitespace)")
        # Giá trị: cắt OWS hai đầu (không phải dữ liệu). Tên: nguyên văn.
        fields["headers"].append([name, value.strip(OWS)])
    return None


def parse_http(payload: bytes) -> ParseResult:
    """Payload TCP -> ParseResult của tầng ứng dụng.

    payload của ParseResult để b"": HTTP là tầng trên cùng của bài 1, không có
    tầng nào nữa để giao bytes lên. Body là DỮ LIỆU CỦA CHÍNH tầng này nên nằm
    trong fields (`body_b64`), không nằm ở `payload`.

    fields luôn khác rỗng kể cả khi có error: một request hỏng ở header thứ 5
    vẫn cho biết method, URI và 4 header đầu — đó là thứ luật phát hiện dùng
    được (§5.4, REQ-7.5).
    """
    # kind suy từ chữ ký ở byte đầu, TRƯỚC khi chia dòng: kể cả khi trong buffer
    # chưa trọn một dòng nào thì event vẫn nói được đây là request hay response.
    kind = "response" if payload.startswith(RESPONSE_PREFIX) else "request"
    fields = _new_fields(kind)

    header_block, body, incomplete = _split_header_and_body(payload)
    fields["incomplete"] = incomplete
    # Điền body TRƯỚC khi parse header: ranh giới body do dòng trống quyết định,
    # thuần vị trí, không phụ thuộc phần header có đúng cú pháp hay không.
    fields["body_len"] = len(body)
    fields["body_b64"] = b64(body)              # I-4: giải mã ngược ra đúng bytes

    raw_lines = header_block.split(CRLF) if header_block else []
    if not raw_lines:
        # Chưa trọn một dòng nào (REQ-7.4). Không phải lỗi: dữ liệu không sai,
        # chỉ là chưa đủ. incomplete=True ở trên đã nói điều đó.
        return ParseResult(fields=fields)

    try:
        start_line = _decode_line(raw_lines[0])
    except UnicodeDecodeError as exc:
        return ParseResult(
            fields=fields,
            error=(f"http start line cannot decode as ascii: "
                   f"byte 0x{raw_lines[0][exc.start]:02x} at offset {exc.start}"),
        )

    if kind == "response":
        error = _parse_status_line(start_line, fields)
    else:
        error = _parse_request_line(start_line, fields)
    if error is not None:
        # Dừng trước phần header: start line sai cú pháp nghĩa là chưa chắc
        # ranh giới dòng ở đây giống cách bên nhận chia (§4.2).
        return ParseResult(fields=fields, error=error)

    error = _parse_headers(raw_lines[1:], fields)
    return ParseResult(fields=fields, error=error)
