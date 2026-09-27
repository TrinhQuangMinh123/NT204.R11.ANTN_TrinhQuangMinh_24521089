"""Tầng ứng dụng: parser DNS trên UDP (REQ-8.1–8.5, Phụ lục A.6, I-6).

Ba parser trước có một điểm chung mà DNS **không** có: mọi trường của chúng đọc
được bằng một phép tính từ đầu buffer. HTTP là văn bản nhưng vẫn đọc tuần tự.
DNS thì có **nén tên** (RFC 1035 §4.1.4): một tên miền được phép kết thúc bằng
một con trỏ 2 byte trỏ **về một vị trí khác trong cùng message**, và tên ở đó
lại được phép kết thúc bằng một con trỏ nữa.

    0  1  2  3  4  5  6  7          <- offset trong payload
   +--+--+--+--+--+--+--+--+
   |06 victim 03 lab 00     |       tên đầy đủ, kết thúc bằng nhãn rỗng
   |C0 0C                   |       "nhảy về offset 0x0C rồi đọc tiếp"
   +--+--+--+--+--+--+--+--+

Nén tên là nguồn của hai lớp bug mà REQ-8.4 nhắm vào:

  * **Vòng lặp.** `C0 0C` đặt tại chính offset 0x0C là một tên tự trỏ vào nó.
    Cài bằng đệ quy -> `RecursionError`; cài bằng `while True` không đếm ->
    treo vĩnh viễn. Cả hai đều là DoS chỉ với 2 byte, và với một IDS thì "treo"
    nghĩa là mù trong suốt thời gian đó.
  * **Trỏ ra ngoài.** Offset 14 bit tối đa là 16383, payload UDP thật thường
    chỉ vài chục byte -> con trỏ có thể chỉ ra ngoài buffer.

Cách chặn ở đây: **tập `seen` các offset đã đọc** (I-6). Đọc lại một offset đã
đọc = vòng lặp, báo lỗi và dừng ngay. Mạnh hơn cách đếm số lần nhảy: bộ đếm
chỉ chặn được sau N lần, còn tập `seen` chặn ngay lần lặp đầu tiên và không cần
chọn N. Kèm thêm hai biên của RFC: mỗi nhãn ≤ 63 byte, cả tên ≤ 255 byte.

Khác biệt thứ hai so với HTTP: **nhãn DNS được phép chứa byte bất kỳ**
(RFC 1035 §3.1), trong khi header HTTP chỉ được phép US-ASCII (RFC 9110 §5.5).
Vì vậy byte lạ trong nhãn KHÔNG phải lỗi — nó còn là hình dạng đặc trưng của
DNS tunneling, đúng thứ cần thấy — nên nhãn được escape thành `\\xHH` chứ không
bị từ chối (xem `_label_to_str`).
"""
import struct

from ..core.event import b64
from .common import ParseResult, need

DNS_HEADER_LEN = 12            # id + flags + 4 con số đếm, mỗi cái 2 byte

# "!HHHHHH" = id, flags, qdcount, ancount, nscount, arcount.
_DNS_HEADER = struct.Struct("!HHHHHH")
_UINT16 = struct.Struct("!H")
# Phần cố định của một resource record sau tên: type, class, ttl, rdlength.
_RR_FIXED = struct.Struct("!HHIH")
_RR_FIXED_LEN = _RR_FIXED.size          # 10

MAX_NAME_LEN = 255             # RFC 1035 §2.3.4
LABEL_TYPE_MASK = 0xC0         # hai bit cao của byte độ dài
LABEL_TYPE_PLAIN = 0x00        # 00 -> nhãn thường, độ dài 0..63
LABEL_TYPE_POINTER = 0xC0      # 11 -> con trỏ nén, 14 bit offset
POINTER_OFFSET_MASK = 0x3F     # 6 bit thấp của byte đầu con trỏ

QR_MASK = 0x8000               # bit 15 của flags
OPCODE_SHIFT, OPCODE_MASK = 11, 0x0F
RCODE_MASK = 0x0F

# Đủ dùng cho bài (lab trả A) + các type hay gặp khi đọc log thật. Số lạ ->
# "TYPE<n>": giữ được con số nên luật phát hiện vẫn viết được, và không bao giờ
# mất thông tin vì một bảng tra thiếu.
RR_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
            16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}

# RDATA của ba type này CHỈ là một tên miền -> phải giải nén tiếp, vì con trỏ
# bên trong RDATA là chuyện thường (CNAME trỏ về tên đã xuất hiện ở question).
NAME_RDATA_TYPES = ("NS", "CNAME", "PTR")

IPV4_LEN, IPV6_LEN = 4, 16

# Đúng 8 khoá của design §5.4 / Phụ lục A.6, luôn có mặt đủ và đúng thứ tự (I-2).
APP_FIELDS = ("id", "qr", "opcode", "rcode", "qdcount", "ancount",
              "questions", "answers")


def _new_fields() -> dict:
    """Khung `app` đủ khoá — các bước sau chỉ ĐIỀN, không THÊM khoá."""
    return {
        "id": None,
        "qr": None,
        "opcode": None,
        "rcode": None,
        "qdcount": 0,
        "ancount": 0,
        "questions": [],
        "answers": [],
    }


def _name_of(table: dict, value: int, prefix: str) -> str:
    """Số -> tên đã biết, hoặc "<PREFIX><số>" nếu chưa biết.

    Tên chứ không phải số vì khác với `status_code` của HTTP: rcode/opcode/type
    là tập giá trị RỜI RẠC, không ai so sánh chúng theo khoảng (không có khái
    niệm "mọi rcode ≥ 3"), nên đổi sang tên chỉ làm luật phát hiện dễ đọc mà
    không mất khả năng so sánh. Ca chưa biết vẫn giữ con số trong chuỗi.
    """
    return table.get(value, f"{prefix}{value}")


def _label_to_str(label: bytes) -> str:
    """Một nhãn -> str, byte không in được thì escape `\\xHH` (không mất dữ liệu).

    Không `decode("ascii")` nghiêm ngặt như header HTTP: RFC 1035 §3.1 cho phép
    nhãn chứa octet bất kỳ, nên byte lạ ở đây là dữ liệu hợp lệ — và chính là
    hình dạng của DNS tunneling (nhãn dài, ký tự bất thường). Từ chối nó là tự
    tạo báo động sai trên đúng loại traffic cần theo dõi.

    Escape thay vì `errors="replace"` vì escape ĐẢO NGƯỢC ĐƯỢC: từ `\\xff` trong
    event dựng lại được byte gốc, còn U+FFFD thì không (I-4).
    """
    out = []
    for byte in label:
        if 0x20 <= byte < 0x7F and byte != 0x5C:      # in được, trừ dấu "\"
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def _read_name(data: bytes, offset: int):
    """Đọc một tên miền từ `offset`. Trả `(name, offset kế tiếp, lỗi)`.

    `offset kế tiếp` là vị trí trong LUỒNG, không phải vị trí con trỏ nhảy tới:
    một tên kết thúc bằng con trỏ thì phần tử tiếp theo của message nằm ngay sau
    2 byte con trỏ đó, bất kể con trỏ trỏ đi đâu. Biến `after` giữ đúng nghĩa
    này: nó chỉ được gán MỘT lần, ở lần nhảy đầu tiên.

    Vòng lặp `while True` chứ không đệ quy (I-6): mỗi lần nhảy con trỏ chỉ là
    một phép gán `cursor`, nên độ sâu ngăn xếp không phụ thuộc dữ liệu của kẻ
    tấn công.
    """
    labels = []
    seen = set()            # offset đã đọc -> đọc lại = vòng lặp (REQ-8.4)
    after = None            # vị trí kế tiếp trong luồng
    total = 0               # tổng độ dài tên, để chặn biên 255 byte
    cursor = offset

    while True:
        if not need(data, cursor, 1):
            return None, after or cursor, (
                f"dns name starting at offset {offset} runs past the end of "
                f"the payload at offset {cursor}")
        if cursor in seen:
            # Đây là ca `C0 0C` tự trỏ vào nó, và cả ca hai con trỏ trỏ vòng
            # cho nhau. Dừng NGAY lần lặp đầu, không cần bộ đếm.
            return None, after or cursor, (
                f"dns name starting at offset {offset} has a compression "
                f"pointer loop back to offset {cursor}")
        seen.add(cursor)

        length = data[cursor]
        label_type = length & LABEL_TYPE_MASK

        if label_type == LABEL_TYPE_POINTER:
            if not need(data, cursor, 2):
                return None, after or cursor, (
                    f"dns compression pointer at offset {cursor} is cut off "
                    f"(needs 2 bytes)")
            pointer = ((length & POINTER_OFFSET_MASK) << 8) | data[cursor + 1]
            if after is None:
                after = cursor + 2
            if pointer >= len(data):
                # REQ-8.4: con trỏ ra ngoài payload. Không dùng nó làm chỉ số —
                # slice của Python sẽ im lặng trả b"" và tên ra sai (I-5).
                return None, after, (
                    f"dns compression pointer at offset {cursor} points to "
                    f"offset {pointer}, outside the {len(data)}-byte payload")
            cursor = pointer
            continue

        if label_type != LABEL_TYPE_PLAIN:
            # Hai giá trị 01 và 10 là RESERVED (RFC 1035 §4.1.4). Chú ý: đây
            # cũng chính là chỗ chặn "nhãn dài hơn 63 byte" — một nhãn thường
            # có hai bit cao bằng 00 nên độ dài tối đa của nó là 0x3F = 63. Byte
            # độ dài 64..191 KHÔNG phải nhãn dài, nó là một loại nhãn không tồn
            # tại; nói đúng lý do đó ra thì thông báo lỗi mới dùng được.
            return None, after or cursor + 1, (
                f"dns label at offset {cursor} has reserved type bits "
                f"0b{label_type >> 6:02b} (length byte 0x{length:02x})")

        if length == 0:
            # Nhãn rỗng = nhãn gốc (root) -> hết tên.
            if after is None:
                after = cursor + 1
            # Tên chỉ có root -> "."; tên thường -> không có dấu chấm cuối, để
            # so sánh trực tiếp với chuỗi mà người viết luật gõ ("victim.lab").
            return (".".join(labels) if labels else "."), after, None

        if not need(data, cursor + 1, length):
            return None, after or cursor, (
                f"dns label at offset {cursor} declares {length} bytes but "
                f"only {len(data) - cursor - 1} remain")

        total += length + 1                     # +1 cho dấu chấm phân cách
        if total > MAX_NAME_LEN:
            # Không có vòng lặp nhưng vẫn có thể phình vô hạn bằng nhiều con trỏ
            # trỏ tới các offset KHÁC nhau -> biên 255 byte của RFC là chốt cuối.
            return None, after or cursor, (
                f"dns name starting at offset {offset} is longer than "
                f"{MAX_NAME_LEN} bytes")

        labels.append(_label_to_str(data[cursor + 1:cursor + 1 + length]))
        cursor += 1 + length


def _format_rdata(type_name: str, rdata: bytes, data: bytes, offset: int):
    """RDATA -> (giá trị cho khoá `data`, lỗi).

    Ca không nhận ra thì trả base64 chứ không bỏ trống (I-4): event vẫn giữ đủ
    bytes để soi lại, và một type lạ không làm mất bản ghi.
    """
    if type_name == "A":
        if len(rdata) != IPV4_LEN:
            return b64(rdata), (f"dns A record has {len(rdata)} bytes of "
                                f"rdata, expected {IPV4_LEN}")
        return ".".join(str(byte) for byte in rdata), None

    if type_name == "AAAA":
        if len(rdata) != IPV6_LEN:
            return b64(rdata), (f"dns AAAA record has {len(rdata)} bytes of "
                                f"rdata, expected {IPV6_LEN}")
        # 8 nhóm hex, KHÔNG rút gọn "::": rút gọn có nhiều ca biên (chỉ được rút
        # một lần, chọn dãy 0 dài nhất) nên hai cách cài đặt cho ra hai chuỗi
        # khác nhau cho cùng một địa chỉ. Dạng đầy đủ thì tất định (NFR-2).
        groups = _UINT16.iter_unpack(rdata)
        return ":".join(f"{group[0]:04x}" for group in groups), None

    if type_name in NAME_RDATA_TYPES:
        # RDATA là một tên, và tên đó được phép dùng con trỏ nén trỏ về phần
        # trước của message -> phải giải bằng chính _read_name trên TOÀN message.
        name, _after, error = _read_name(data, offset)
        if error is not None:
            return b64(rdata), error
        return name, None

    return b64(rdata), None


def _read_question(data: bytes, offset: int):
    """Một entry của question section -> `({name, type}, offset kế tiếp, lỗi)`."""
    name, cursor, error = _read_name(data, offset)
    if error is not None:
        return None, cursor, error
    # QTYPE + QCLASS = 4 byte. Không ghi QCLASS vào event: design §5.4 không có
    # khoá đó, và mọi truy vấn trong bài đều là class IN (1).
    if not need(data, cursor, 4):
        return None, cursor, (f"dns question at offset {offset} is missing "
                              f"qtype/qclass (needs 4 bytes)")
    qtype = _UINT16.unpack_from(data, cursor)[0]
    return ({"name": name, "type": _name_of(RR_TYPES, qtype, "TYPE")},
            cursor + 4, None)


def _read_answer(data: bytes, offset: int):
    """Một resource record -> `({name, type, ttl, data}, offset kế tiếp, lỗi)`."""
    name, cursor, error = _read_name(data, offset)
    if error is not None:
        return None, cursor, error
    if not need(data, cursor, _RR_FIXED_LEN):
        return None, cursor, (f"dns answer at offset {offset} is missing its "
                              f"{_RR_FIXED_LEN}-byte fixed part")
    rtype, _rclass, ttl, rdlength = _RR_FIXED.unpack_from(data, cursor)
    cursor += _RR_FIXED_LEN
    type_name = _name_of(RR_TYPES, rtype, "TYPE")

    if not need(data, cursor, rdlength):
        # Bản ghi tự khai độ dài RDATA -> lại là một con số của kẻ gửi, phải
        # kiểm trước khi cắt (cùng lý lẽ với `length` của UDP).
        return ({"name": name, "type": type_name, "ttl": ttl, "data": None},
                cursor, f"dns answer {name!r} declares {rdlength} bytes of "
                        f"rdata but only {len(data) - cursor} remain")

    value, error = _format_rdata(type_name, data[cursor:cursor + rdlength],
                                 data, cursor)
    return ({"name": name, "type": type_name, "ttl": ttl, "data": value},
            cursor + rdlength, error)


def parse_dns(payload: bytes) -> ParseResult:
    """Payload UDP -> ParseResult của tầng ứng dụng.

    Giữ mọi bản ghi đã parse được KỂ CẢ khi có lỗi (REQ-8.5): `ParseResult` cho
    phép `fields` và `error` cùng khác rỗng. Một response khai ANCOUNT=5 mà chỉ
    có 1 answer thật vẫn để lại 1 answer đó trong event — đây thường là dấu hiệu
    dữ liệu bị dựng tay, nên thứ đã đọc được là bằng chứng, không phải rác.

    KHÔNG đọc authority/additional section: Phụ lục A.6 và design §5.4 chỉ yêu
    cầu question + answer. Byte còn lại sau answer cuối vì thế KHÔNG bị coi là
    lỗi — khác với UDP (`length` phải khớp đúng), vì ở đây các con số đếm nói rõ
    phần nào thuộc phần nào.
    """
    fields = _new_fields()

    if not need(payload, 0, DNS_HEADER_LEN):
        return ParseResult(
            fields=fields,
            error=f"dns header needs {DNS_HEADER_LEN} bytes, got {len(payload)}",
        )

    (ident, flags, qdcount, ancount,
     _nscount, _arcount) = _DNS_HEADER.unpack_from(payload, 0)

    fields["id"] = ident
    # QR là MỘT bit: 0 = query, 1 = response. Ghi thành chuỗi (ADR-6: event là
    # dữ liệu để đọc và để viết luật, không phải ảnh chụp bit).
    fields["qr"] = "response" if flags & QR_MASK else "query"
    fields["opcode"] = _name_of(OPCODES, (flags >> OPCODE_SHIFT) & OPCODE_MASK,
                                "OPCODE")
    fields["rcode"] = _name_of(RCODES, flags & RCODE_MASK, "RCODE")
    # Ghi con số BÊN GỬI KHAI, không phải `len(questions)`: hai số lệch nhau
    # chính là REQ-8.5, nên chúng phải nằm ở hai chỗ khác nhau trong event.
    fields["qdcount"] = qdcount
    fields["ancount"] = ancount

    cursor = DNS_HEADER_LEN

    for index in range(qdcount):
        question, cursor, error = _read_question(payload, cursor)
        if error is not None:
            return ParseResult(
                fields=fields,
                error=f"dns question {index + 1}/{qdcount}: {error}")
        fields["questions"].append(question)

    for index in range(ancount):
        answer, cursor, error = _read_answer(payload, cursor)
        if answer is not None:
            # Thêm TRƯỚC khi xét lỗi: một answer đọc được một phần (vd rdlength
            # khai quá dài) vẫn cho biết tên, type và TTL (REQ-8.5, REQ-14.1).
            fields["answers"].append(answer)
        if error is not None:
            return ParseResult(
                fields=fields,
                error=f"dns answer {index + 1}/{ancount}: {error}")

    return ParseResult(fields=fields)


def question_section_fits(payload: bytes) -> bool:
    """Chữ ký nhận diện DNS của Phụ lục C — dùng bởi `matches_dns` ở detector.

    "Payload ≥ 12 byte, QDCOUNT ≥ 1, toàn bộ phần question parse được trong
    phạm vi payload." Đặt ở đây (cạnh parser) chứ không viết lại trong
    `detector.py` vì nó là công việc BYTE-LEVEL của DNS; detector chỉ được biết
    "khớp hay không" (NFR-6: thêm giao thức = thêm một dòng registry).

    DNS không có magic number nào ở đầu payload — 2 byte đầu là transaction ID,
    tức 65536 giá trị đều hợp lệ. Vì vậy chữ ký buộc phải là "cấu trúc tự nhất
    quán": các con số đếm trong header phải giải thích được đúng số byte đi sau.
    """
    if not need(payload, 0, DNS_HEADER_LEN):
        return False
    qdcount = _DNS_HEADER.unpack_from(payload, 0)[2]
    if qdcount < 1:
        return False
    cursor = DNS_HEADER_LEN
    for _ in range(qdcount):
        _question, cursor, error = _read_question(payload, cursor)
        if error is not None:
            return False
    return True
