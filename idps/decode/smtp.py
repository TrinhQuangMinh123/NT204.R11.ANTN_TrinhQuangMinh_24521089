"""Tầng ứng dụng: parser SMTP (REQ-9.1-9.3, Phụ lục A.7, ADR-5).

SMTP cũng là giao thức văn bản như HTTP, nhưng cấu trúc đơn giản hơn một bậc:
không có "khối header + dòng trống + body" nào để đi tìm, chỉ có **dòng**. Mỗi
dòng kết thúc bằng CRLF và chỉ mang đúng một trong hai hình dạng (RFC 5321 §4.1,
§4.2):

    C: EHLO attacker.lab\\r\\n         command  = <VERB> [ SP <argument> ]
    S: 250-victim.lab\\r\\n            reply    = <3 chữ số><"-" | " "><text>
    S: 250-SIZE 33554432\\r\\n                    "-" = CÒN dòng nữa
    S: 250 HELP\\r\\n                             " " = dòng CUỐI (§4.2.1)

Vì vậy parser này không có bước "tìm dấu phân cách" nào phức tạp; chỗ khó nằm ở
bốn quyết định khác:

  * **Nhận ra loại bằng 4 byte đầu, không bằng port hay hướng gói.** `sport=25`
    chỉ là một con số bên gửi tự chọn, còn ba chữ số theo sau dấu cách hoặc "-"
    là hình dạng mà chỉ một reply có. Nhờ vậy parser đúng kể cả trên gói giả mạo
    hoặc trên phiên SMTP chạy ở port lạ (REQ-11.3).
  * **Tên lệnh được chuẩn hoá thành CHỮ HOA.** RFC 5321 §2.4: lệnh không phân
    biệt hoa thường, nên `mail from:` và `MAIL FROM:` là CÙNG một lệnh — luật
    phát hiện sau này không được phải liệt kê 2^9 cách viết. Đây là chỗ ngược
    với HTTP: `parse_http` giữ nguyên văn `method` vì RFC 9110 §9.1 nói method
    PHÂN BIỆT hoa thường ("get" là method khác, không hợp lệ). Bản gốc từng byte
    vẫn còn trong `tcp.payload_b64` của cùng event nên không mất bằng chứng (I-4).
  * **`MAIL FROM` và `RCPT TO` là tên lệnh CÓ DẤU CÁCH.** `line.split(" ")` sẽ
    cho `command="MAIL"`, `argument="FROM:<a@b>"` — sai cả hai trường. Nên tên
    lệnh được cắt theo ĐỘ DÀI CHỮ KÝ (bảng `COMMANDS`), không cắt theo dấu cách.
  * **CR hoặc LF đứng lẻ là lỗi được ghi, không phải chuyện bỏ qua.** RFC 5321
    §2.3.8 buộc dòng kết thúc bằng đúng CRLF. Một `\\n` trần ở đây chính là hình
    dạng của SMTP smuggling (CVE-2023-51764): bên gửi và bên nhận hiểu khác nhau
    về dấu kết thúc dòng/kết thúc thư, và kẻ tấn công nhồi được một thư thứ hai
    vào giữa. Cùng lý lẽ với việc `parse_http` chỉ chấp nhận CRLF.

Giới hạn theo giả định A2 (không ghép luồng TCP): parser chỉ thấy phần SMTP nằm
TRONG MỘT segment. Hệ quả cụ thể — một reply nhiều dòng bị cắt giữa hai segment
thì packet này chỉ có các dòng của nó; và dữ liệu thư sau lệnh `DATA` không mang
chữ ký nào của Phụ lục C nên detector trả `UNKNOWN`, không phải lỗi.
"""
from .common import ParseResult

CRLF = b"\r\n"
_CR, _LF = 0x0D, 0x0A
OWS = " \t"                     # khoảng trắng quanh tham số, không phải dữ liệu
DIGITS = b"0123456789"
REPLY_CODE_LEN = 3              # RFC 5321 §4.2: mã trả lời đúng 3 chữ số
# " " = dòng cuối của reply, "-" = còn dòng nữa (§4.2.1). Cả hai đều là PHẦN
# BẮT BUỘC của chữ ký: thiếu nó thì một body HTTP mở đầu bằng "404" cũng thành
# reply SMTP.
REPLY_SEPARATORS = (b" ", b"-")

# Đúng 10 lệnh của Phụ lục C (4 lệnh bắt buộc của REQ-9.1 + 6 lệnh thêm ở v4).
# Danh sách ĐÓNG: nới ra là nới cả bề mặt nhận nhầm trên port lạ (R5).
# Hai lệnh đầu chứa dấu ":" trong chính chữ ký — xem `_argument_of`.
# Không lệnh nào là tiền tố của lệnh khác, nên thứ tự trong tuple không ảnh
# hưởng kết quả; để "MAIL FROM:"/"RCPT TO:" lên đầu chỉ cho dễ đọc.
COMMANDS = (b"MAIL FROM:", b"RCPT TO:", b"STARTTLS", b"HELO", b"EHLO",
            b"DATA", b"QUIT", b"RSET", b"NOOP", b"AUTH")
COLON_COMMANDS = ("MAIL FROM", "RCPT TO")
_MAX_COMMAND_LEN = max(len(verb) for verb in COMMANDS)

# Đúng 5 khoá của Phụ lục A.7 / design §5.4, LUÔN có mặt đủ và đúng thứ tự:
# khoá không áp dụng để null (`status_code` của một command). Nhờ vậy module bài
# sau đọc app["command"] được mà không cần .get() (I-2).
APP_FIELDS = ("kind", "command", "argument", "status_code", "lines")


def _new_fields(kind: str) -> dict:
    """Khung `app` đủ khoá — các bước sau chỉ ĐIỀN, không THÊM khoá."""
    return {
        "kind": kind,
        "command": None,
        "argument": None,
        "status_code": None,
        "lines": [],
    }


# --- chữ ký Phụ lục C (dùng bởi detector qua `matches_smtp`) -----------------

def reply_code_at_start(payload: bytes) -> int | None:
    """Mã trả lời nếu payload mở đầu đúng chữ ký reply, ngược lại None.

    Chữ ký Phụ lục C: "3 chữ số theo sau là dấu cách hoặc `-`". Trả về SỐ chứ
    không phải bool để `parse_smtp` khỏi phải đọc lại 4 byte đó lần thứ hai.

    So sánh từng byte với `DIGITS` thay vì `bytes.isdigit()` để giữ đúng một lối
    viết với `_parse_status_line` của HTTP, nơi phải tránh `str.isdigit()` vì nó
    trả True cho chữ số của hệ chữ khác (vd "\u0662\u0665\u0660") và `int()` sau đó
    cho ra một con số không ai gửi. Tập ký tự tường minh thì không có ngoại lệ
    ngầm nào, ở cả hai kiểu bytes và str.

    KHÔNG kiểm chữ số đầu phải trong 2..5: Phụ lục C chỉ nói "3 chữ số", và một
    mã lạ (`999 `) vẫn là dữ liệu cần thấy chứ không phải lỗi của parser. Giá
    phải trả là rủi ro R5 — xem `matches_smtp` ở detector.
    """
    if len(payload) < REPLY_CODE_LEN + 1:
        # Thiếu cả dấu phân cách -> chưa đủ để kết luận. Không đoán: 3 byte
        # "250" có thể là đầu của "250 OK" mà cũng có thể là một body bất kỳ.
        return None
    code = payload[:REPLY_CODE_LEN]
    if any(byte not in DIGITS for byte in code):
        return None
    if payload[REPLY_CODE_LEN:REPLY_CODE_LEN + 1] not in REPLY_SEPARATORS:
        return None
    return int(code)


def reply_shape_fits(payload: bytes) -> bool:
    """Chữ ký nhận diện reply của Phụ lục C **sau khi siết ở T9.2b** (req v8).

    Ba điều kiện, tất cả đều là bất biến CẤU TRÚC của một reply (RFC 5321 §4.2):

      1. payload mở đầu bằng 3 chữ số + `[ -]` (`reply_code_at_start`);
      2. có ít nhất một dòng kết thúc bằng CRLF — không kết luận trên dữ liệu
         chưa trọn một dòng;
      3. **mọi** dòng đã kết thúc trong payload đều khớp văn phạm reply.

    Vì sao phải siết: chữ ký cũ chỉ xét 4 byte đầu, trong đó **chỉ 1 byte là
    hằng số**. Một mảnh body HTTP ở GIỮA luồng (`404 page not found\r\n<hr>
    nginx\r\n`) không còn chữ ký HTTP nào — chữ ký HTTP chỉ có ở segment ĐẦU —
    nên nó khớp chữ ký reply và event ghi `app_proto="SMTP"` trên một phiên port
    80. Đo trên 10 000 mẫu văn bản sinh có seed cố định: **49,9% → 27,0%**, trong
    khi 10/10 payload reply thật của TC-10 vẫn khớp (ADR-5, bảng số đo).

    Đây cũng là điều làm SMTP thống nhất với DNS: cả hai chữ ký giờ đều là
    **probing parser** (thử parse), không phải so tiền tố — vì cả hai đều thiếu
    một chuỗi mở đầu dài và hiếm như `GET ` hay `HTTP/1.`.

    **Cố tình KHÔNG đòi mọi dòng cùng một mã**, dù RFC 5321 §4.2.1 buộc vậy:
    luật đó là bất biến của MỘT reply, không phải của một SEGMENT. RFC 2920
    (PIPELINING) cho phép server gộp reply của nhiều lệnh vào một segment, ví dụ
    `250 OK` `250 OK` `550 no such user` — traffic hợp lệ mà điều kiện "cùng mã"
    sẽ bỏ sót (đo được 17,5% nhận nhầm nhưng mất ca này). Việc phát hiện mã
    không đồng nhất vì thế thuộc về parser (`_parse_response` báo lỗi) chứ không
    thuộc về chữ ký.
    """
    if reply_code_at_start(payload) is None:
        return False
    lines = payload.split(CRLF)[:-1]
    if not lines:
        return False
    # decode("latin-1") thay vì "ascii": mỗi byte thành đúng một ký tự và
    # KHÔNG BAO GIỜ ném. Ở đây ta chỉ hỏi về HÌNH DẠNG, mà hình dạng chỉ gồm
    # byte ASCII (3 chữ số + phân cách) nên latin-1 không làm sai kết quả. Nếu
    # dùng "ascii" nghiêm ngặt thì một byte > 0x7F trong phần text sẽ làm chữ ký
    # TRƯỢT → event ra `UNKNOWN`, và cái lỗi "byte > 0x7F trong reply SMTP" —
    # đúng thứ một IDS cần thấy — sẽ không bao giờ được báo (§8.2). Tức là:
    # chữ ký xét hình dạng (dễ tính với byte lạ), parser xét nội dung (nghiêm
    # ngặt, và báo lỗi). Cùng MỘT hàm văn phạm `_reply_code_of_line` cho cả hai
    # nên hai nơi không thể lệch nhau về định nghĩa "thế nào là một dòng reply".
    return all(_reply_code_of_line(raw.decode("latin-1"))[0] is not None
               for raw in lines)


def command_at_start(payload: bytes) -> str | None:
    """Tên lệnh (chuẩn hoá HOA) nếu payload mở đầu bằng một lệnh Phụ lục C.

    `upper()` trên bytes chỉ đổi a-z, byte > 0x7F giữ nguyên và không ném — nên
    payload nhị phân đi qua đây an toàn (I-5).

    Dấu phân cách phía sau tên lệnh là PHẦN BẮT BUỘC của chữ ký, đúng như dấu
    cách sau method của HTTP: cho phép SP (lệnh có tham số), CR/LF (lệnh không
    tham số, `QUIT\\r\\n`), hoặc hết payload (segment cắt ngay sau tên lệnh).
    Không có nó thì `EHLOX` hay một payload nhị phân tình cờ bắt đầu bằng
    b"DATA" cũng bị nhận là SMTP.

    KHÔNG chấp nhận TAB làm phân cách: RFC 5321 §4.1.1 chỉ cho SP. Dễ tính hơn
    RFC ở chỗ này là tự tạo ra một cách đọc thứ hai cho cùng một dòng — đúng
    điều kiện của một cuộc tấn công desync.
    """
    head = payload[:_MAX_COMMAND_LEN].upper()
    for verb in COMMANDS:
        if not head.startswith(verb):
            continue
        if verb.endswith(b":"):
            # "MAIL FROM:<a@b>" hợp lệ, không cần dấu cách sau dấu ":"
            # (RFC 5321 §4.1.2) -> chính dấu ":" là phân cách.
            return verb[:-1].decode("ascii")
        after = payload[len(verb):len(verb) + 1]
        if after in (b"", b" ", b"\r", b"\n"):
            return verb.decode("ascii")
    return None


# --- các bước parse ---------------------------------------------------------

def _split_lines(payload: bytes):
    """payload -> (các dòng ĐÃ kết thúc, phần dư sau CRLF cuối).

    Phần dư bị tách ra chứ không coi là một dòng: khi chưa thấy CRLF thì dòng đó
    có thể đang bị cắt giữa, và `250-siz` có thể là phần đầu của
    `250-SIZE 33554432`. Lấy nó vào `lines` là ghi một giá trị sai mà không có
    lỗi nào báo — cùng lý lẽ với `_split_header_and_body` của HTTP (REQ-7.4).
    """
    parts = payload.split(CRLF)
    return parts[:-1], parts[-1]


def _decode_line(raw: bytes) -> str:
    """bytes -> str ASCII nghiêm ngặt. UnicodeDecodeError -> người gọi bắt.

    Nghiêm ngặt như HTTP, KHÁC nhãn DNS (được escape `\\xHH`): nhãn DNS được
    phép chứa octet bất kỳ (RFC 1035 §3.1), còn lệnh và reply SMTP thì RFC 5321
    §2.3.1 quy định là US-ASCII 7 bit. Byte > 0x7F ở đây là bất thường thật —
    thường là nhồi dữ liệu qua bộ lọc hoặc thử tràn bộ đệm của server — nên nó
    phải thành một lỗi có trong event, không phải một ký tự U+FFFD im lặng.
    """
    return raw.decode("ascii")


def _reply_code_of_line(line: str):
    """Một dòng BÊN TRONG reply -> (mã, phần text). (None, "") nếu không phải.

    Nới hơn `reply_code_at_start` đúng một ca: cho phép 3 chữ số rồi HẾT DÒNG,
    vì RFC 5321 §4.2 ghi `Reply-code [ SP textstring ] CRLF` — phần SP và text
    là TUỲ CHỌN, nên `250\\r\\n` là một reply hợp lệ không có text.

    Vì sao hai hàm lại khác nhau: `reply_code_at_start` là chữ ký NHẬN DIỆN,
    chạy trên mọi payload TCP chưa biết là gì, nên phải hẹp nhất có thể (một
    payload 3 byte "250" thì đoán gì cũng là đoán). Hàm này chỉ chạy khi đã
    biết chắc đang ở trong một message SMTP, nên dùng được trọn văn phạm RFC.
    """
    code = line[:REPLY_CODE_LEN]
    if len(code) != REPLY_CODE_LEN or not code.isascii() or not code.isdigit():
        return None, ""
    separator = line[REPLY_CODE_LEN:REPLY_CODE_LEN + 1]
    if separator == "":
        return int(code), ""
    if separator not in (" ", "-"):
        return None, ""
    return int(code), line[REPLY_CODE_LEN + 1:]


def _parse_response(raw_lines: list, code: int, fields: dict) -> str | None:
    """Các dòng của một reply -> status_code + lines. Trả lý do lỗi hoặc None.

    REQ-9.3 "một status code chung": mã lấy từ dòng ĐẦU. RFC 5321 §4.2.1 buộc
    mọi dòng của một reply mang cùng mã, nên dòng sau khai mã khác là dữ liệu
    bất thường -> vẫn GIỮ các dòng đã đọc rồi báo lỗi (design §8.2), giống DNS
    giữ answer khi ANCOUNT khai sai (REQ-8.5).
    """
    fields["status_code"] = code
    for number, raw in enumerate(raw_lines, start=1):
        try:
            line = _decode_line(raw)
        except UnicodeDecodeError as exc:
            # Ghi số dòng và vị trí byte để soi lại bằng xxd được ngay.
            return (f"smtp response line {number} cannot decode as ascii: "
                    f"byte 0x{raw[exc.start]:02x} at offset {exc.start}")
        line_code, text = _reply_code_of_line(line)
        if line_code is None:
            # Một dòng không phải reply line nằm giữa reply: dừng ở đây, giữ
            # các dòng trước. Đọc tiếp là tự đoán bên nhận hiểu thế nào (§4.2).
            return (f"smtp response line {number} is not a reply line: "
                    f"{line!r}")
        # Thêm TRƯỚC khi so mã: dòng này đã decode trọn nên text của nó là dữ
        # liệu thật, là bằng chứng — không phải rác (REQ-14.1).
        fields["lines"].append(text)
        if line_code != code:
            return (f"smtp response line {number} declares code {line_code}, "
                    f"line 1 declared {code}")
    return None


def _argument_of(line: str, command: str) -> str | None:
    """Phần sau tên lệnh -> argument. None = lệnh không có tham số.

    Cắt theo ĐỘ DÀI TÊN LỆNH chứ không theo dấu cách đầu tiên, vì "MAIL FROM"
    và "RCPT TO" chứa một dấu cách trong chính tên: `line.split(" ", 1)` sẽ cho
    `command="MAIL"` và `argument="FROM:<a@b>"`.

    Phân biệt `None` với `""`: `QUIT` không có chỗ cho tham số -> None;
    `HELO ` (có dấu cách rồi hết dòng) -> "" nghĩa là "có chỗ nhưng bỏ trống",
    một lỗi cú pháp của client mà luật phát hiện có thể quan tâm.

    Cắt OWS hai đầu của tham số (không phải dữ liệu, `MAIL FROM: <a@b>` là cách
    viết nhiều client dùng), đúng như HTTP cắt OWS quanh GIÁ TRỊ header.
    """
    length = len(command) + (1 if command in COLON_COMMANDS else 0)
    rest = line[length:]
    if rest == "":
        return None
    return rest.strip(OWS)


def _parse_command(raw_lines: list, partial: bytes, fields: dict) -> str | None:
    """Các dòng lệnh -> command + argument + lines. Trả lý do lỗi hoặc None.

    Tên lệnh đọc từ dòng đầu KỂ CẢ khi dòng đó chưa kết thúc: tên lệnh và dấu
    phân cách của nó nằm trong vài byte đầu, một segment bị cắt phía sau không
    đổi được chúng. Nhưng `argument` thì CHỈ điền khi dòng đã kết thúc —
    `RCPT TO:<admin@` ghi ra như một địa chỉ đầy đủ là một lời nói dối, mà đó
    đúng là trường luật phát hiện sẽ đem đi so.

    SMTP chạy lock-step (gửi một lệnh, chờ một reply) nên gần như luôn chỉ có
    một lệnh trong một segment; `lines` vẫn giữ ĐỦ mọi dòng để thấy ca
    pipelining (RFC 2920), nơi client gửi nhiều lệnh trong một segment — một
    hình dạng đáng để ý vì nó rút ngắn thời gian của kẻ gửi thư rác.
    """
    first = raw_lines[0] if raw_lines else partial
    # Gán trước khi decode: kể cả khi dòng có byte lạ ở giữa thì event vẫn nói
    # được đây là lệnh gì (REQ-14.1, cùng lối với `method` của HTTP).
    fields["command"] = command_at_start(first)

    for number, raw in enumerate(raw_lines, start=1):
        try:
            line = _decode_line(raw)
        except UnicodeDecodeError as exc:
            return (f"smtp command line {number} cannot decode as ascii: "
                    f"byte 0x{raw[exc.start]:02x} at offset {exc.start}")
        fields["lines"].append(line)

    if fields["command"] is None:
        # Không phải reply, cũng không phải lệnh nào của Phụ lục C. Qua pipeline
        # thì ca này KHÔNG xảy ra được (detector chỉ gán SMTP khi một trong hai
        # chữ ký khớp), nhưng parser vẫn phải trả lời trung thực khi bị gọi
        # trực tiếp — bởi unit test hôm nay, và bởi module ghép luồng TCP của
        # bài sau, nơi byte đầu segment không còn là byte đầu message.
        return (f"smtp line 1 {first[:32]!r} is neither a reply line nor a "
                f"command in the known set")

    if fields["lines"]:
        fields["argument"] = _argument_of(fields["lines"][0], fields["command"])
    return None


def stray_eol_offset(payload: bytes) -> int | None:
    """Vị trí một CR hoặc LF đứng lẻ (không thuộc một cặp CRLF), hoặc None.

    RFC 5321 §2.3.8: dòng kết thúc bằng ĐÚNG CRLF, và CR hay LF đứng một mình
    "MUST NOT" xuất hiện. Đây không phải chuyện khó tính về hình thức: chênh
    lệch cách hiểu dấu kết thúc dòng giữa hai phần mềm chính là SMTP smuggling
    (CVE-2023-51764) — server biên nhận `\\n.\\n` là hết thư còn server trong
    nhà thì không (hoặc ngược lại), nên kẻ tấn công nhồi được một thư thứ hai
    mang người gửi giả vào giữa. Một IDS phải NHÌN THẤY hình dạng đó, nên nó
    thành một lỗi trong event chứ không bị bỏ qua.
    """
    for index, byte in enumerate(payload):
        if byte == _LF and (index == 0 or payload[index - 1] != _CR):
            return index
        if byte == _CR and payload[index + 1:index + 2] != b"\n":
            return index
    return None


def parse_smtp(payload: bytes) -> ParseResult:
    """Payload TCP -> ParseResult của tầng ứng dụng.

    `payload` của ParseResult để b"": SMTP là tầng trên cùng của bài 1, không có
    tầng nào nữa để giao bytes lên.

    Thứ tự báo lỗi: lỗi parse (mã không đồng nhất, byte không decode được, dòng
    lạ) được ưu tiên hơn lỗi CRLF lẻ, vì nó chỉ đúng vào TRƯỜNG nào trong event
    không tin được — thông tin hành động được ngay. Lỗi CRLF lẻ chỉ báo khi
    không còn lỗi nào khác; hình dạng của nó vẫn luôn còn nguyên trong
    `tcp.payload_b64` nên không có bằng chứng nào mất đi. (`ParseResult.error`
    là MỘT chuỗi — mỗi tầng góp đúng một lý do vào `errors` của event.)
    """
    raw_lines, partial = _split_lines(payload)
    # Loại suy từ dòng đầu, kể cả dòng chưa kết thúc: 4 byte đầu đã đủ, và một
    # event nói được "đây là reply" vẫn hữu ích khi phần còn lại bị cắt.
    first = raw_lines[0] if raw_lines else partial
    code = reply_code_at_start(first)

    fields = _new_fields("response" if code is not None else "command")
    if code is not None:
        error = _parse_response(raw_lines, code, fields)
    else:
        error = _parse_command(raw_lines, partial, fields)

    if error is None:
        stray = stray_eol_offset(payload)
        if stray is not None:
            error = (f"smtp line ending is not crlf: stray "
                     f"0x{payload[stray]:02x} at offset {stray}")

    return ParseResult(fields=fields, error=error)
