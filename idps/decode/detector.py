"""Nhận diện application protocol (REQ-10, REQ-11, ADR-5, design §6).

Vì sao tầng này phải tồn tại: header của IPv4 có trường `protocol`, header của
Ethernet có `ethertype` — đọc một con số là biết tầng trên là gì. Header TCP và
UDP KHÔNG có trường nào như vậy (vì thế `parse_tcp`/`parse_udp` để
`next_proto = None`). Thứ duy nhất gợi ý là port, mà port là thứ bên gửi tự
chọn: dựng một web server ở port 4444 không sai gì cả.

Nên ADR-5: **port quyết định THỨ TỰ THỬ, payload quyết định KẾT QUẢ.**
  - Chỉ xét port  -> HTTP ở port 8081 bị bỏ sót (mất REQ-11.1).
  - Chỉ xét payload -> vẫn đúng, nhưng phải thử hết mọi giao thức mỗi packet;
    và khi hai chữ ký cùng khớp thì không có căn cứ nào để chọn.
  - Xét port trước rồi payload -> ca thường gặp (port chuẩn) khớp ngay từ ứng
    viên đầu, ca port lạ vẫn ra đúng kết quả, và `detect_method` ghi lại được
    chương trình đã dựa vào đâu (REQ-10.4).

Registry `APP_PROTOCOLS` là điểm mở rộng (NFR-6): thêm một giao thức = thêm một
hàm `matches_*` ngay cạnh đây + một dòng trong tuple. Không sửa `detect()`,
không sửa parser của giao thức khác. DNS vào theo đúng đường đó ở T8.2 và SMTP ở
T9.2 — `git show --stat` của cả hai commit chỉ có `detector.py` + test (+ dòng
khai báo AI trong README).
"""
from dataclasses import dataclass
from typing import Callable

from .common import ParseResult
from .dns import parse_dns, question_section_fits
from .http import parse_http
from .smtp import command_at_start, parse_smtp, reply_shape_fits


@dataclass(frozen=True)
class Detection:
    """Kết quả nhận diện (design §5.3) — KHÔNG phải kết quả parse.

    app_proto: "HTTP"/"SMTP"/"DNS" | "UNKNOWN" (có payload, không giao thức nào
    khớp) | None (payload rỗng — REQ-15.4: rỗng không phải lỗi, cũng không phải
    "không nhận ra", đơn giản là không có gì để nhận).

    method: "port+payload" | "payload". CỐ TÌNH không có giá trị "port" đơn lẻ:
    REQ-10.2 buộc payload phải khớp mới được gán giao thức, nên không tồn tại
    trường hợp kết luận dựa trên port mà chưa xem payload.

    Đặt ở đây chứ không ở common.py như ParseResult vì lý do đối xứng:
    ParseResult có NHIỀU nơi sinh ra (mọi parser) nên cần một nhà trung lập;
    Detection chỉ có đúng một nơi sinh ra là detect() ngay dưới đây.
    """

    app_proto: str | None
    method: str | None


@dataclass(frozen=True)
class AppProto:
    """Một dòng của registry (design §6).

    matches/parse là hàm lưu trong THUỘC TÍNH CỦA INSTANCE, không phải thuộc
    tính của class, nên `proto.matches(payload)` KHÔNG tự truyền self — dataclass
    gán chúng trong __init__. (Nếu viết `matches = matches_http` ở thân class
    thì Python coi là method và sẽ truyền self.)
    """

    name: str                                   # tên ghi vào event["app_proto"]
    transport: str                              # "TCP" | "UDP" — phải khớp mới xét
    ports: tuple                                # port chuẩn (Phụ lục C)
    matches: Callable[[bytes], bool]            # chữ ký payload (Phụ lục C)
    # Parser của giao thức. None = đã nhận diện được tên nhưng bài chưa có
    # parser -> pipeline ghi app_proto và để app = null. T6.3 điền parse_http.
    parse: Callable[[bytes], ParseResult] | None = None


# --- HTTP (Phụ lục C, REQ-10.3) ---------------------------------------------

# Đúng 6 method của REQ-10.3. Không thêm TRACE/CONNECT/PATCH: chữ ký nhận diện
# là một danh sách ĐÓNG có trong yêu cầu, nới ra là nới cả bề mặt nhận nhầm.
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")

# Dấu cách phía sau là phần BẮT BUỘC của chữ ký: request line là
# "METHOD SP request-target SP HTTP-version" (RFC 9112 §3), nên sau method
# luôn có đúng một dấu cách. Không có nó thì "GETX /" hay một payload nhị phân
# tình cờ bắt đầu bằng "PUT" cũng bị nhận là HTTP.
HTTP_REQUEST_PREFIXES = tuple(f"{method} ".encode("ascii")
                              for method in HTTP_METHODS)

# Response bắt đầu bằng status line "HTTP-version SP status-code ...".
# "HTTP/1." chứ không phải "HTTP/": loại HTTP/2 (chữ ký kết nối của nó là
# "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" và phần thân là frame nhị phân, parser
# HTTP/1.x ở T6.3 đọc vào sẽ ra rác).
HTTP_RESPONSE_PREFIX = b"HTTP/1."


def matches_http(payload: bytes) -> bool:
    """True nếu payload mở đầu đúng chữ ký HTTP/1.x (REQ-10.3).

    Chỉ xét PHẦN ĐẦU payload, không quét cả nội dung: một file ảnh tải lên qua
    POST có thể chứa chuỗi "GET " ở giữa, và một payload bất kỳ càng dài thì
    càng dễ tình cờ chứa chuỗi đó. Giao thức thì luôn tự giới thiệu ở byte đầu.

    bytes.startswith nhận tuple -> một lần gọi thay cho vòng lặp, và không có
    phép chỉ số nào nên payload rỗng hay 1 byte cũng không ném (I-5).
    """
    return (payload.startswith(HTTP_REQUEST_PREFIXES)
            or payload.startswith(HTTP_RESPONSE_PREFIX))


# --- SMTP (Phụ lục C, REQ-9, REQ-11.3) --------------------------------------

def matches_smtp(payload: bytes) -> bool:
    """True nếu payload mở đầu đúng một trong HAI chữ ký SMTP (Phụ lục C).

    SMTP là giao thức duy nhất trong bài có hai chữ ký khác nhau cho hai chiều,
    vì nó là giao thức ĐỐI THOẠI theo lượt: client gửi lệnh bằng chữ, server
    đáp bằng số. HTTP cũng hai chiều nhưng cả hai chiều đều mở đầu bằng chữ
    ("GET " / "HTTP/1."), còn DNS thì hai chiều dùng CÙNG một khuôn header.

    Cả hai phép kiểm byte-level nằm trong `smtp.py` chứ không viết lại ở đây —
    cùng lý lẽ với `dns.question_section_fits()`: chúng là văn phạm của SMTP,
    và registry chỉ được biết "khớp hay không" (NFR-6). Thêm nữa, hai hàm đó
    được `parse_smtp` dùng lại y nguyên, nên KHÔNG có cách nào để chữ ký nhận
    diện và parser lệch nhau về định nghĩa "thế nào là một lệnh".

    Rủi ro R5 và cách xử lý (T9.2b, requirements v8): chữ ký reply từng chỉ xét
    4 byte đầu, trong đó chỉ 1 byte là hằng số — quá ngắn, nên một mảnh body HTTP
    ở giữa luồng (`404 page not found…`) cũng khớp và bị gán SMTP trên port 80.
    Nay nó là **probing parser** (`reply_shape_fits`): mọi dòng đã kết thúc trong
    payload đều phải khớp văn phạm reply. Đo được 49,9% → 27,0% nhận nhầm trên
    10 000 mẫu văn bản ngẫu nhiên, và 10/10 reply thật của TC-10 vẫn khớp.

    Phần 27,0% còn lại KHÔNG xử lý được ở bài 1: một dòng đơn `404 page not
    found\r\n` về cú pháp **đúng là** một reply hợp lệ. Muốn phân biệt phải biết
    đây là *giữa* một luồng đã nhận là HTTP — tức cần bảng flow, đúng cách
    Suricata (cache `f->alproto` sau khi nhận diện trên data đầu tiên của mỗi
    chiều), nDPI (`NDPI_EXCLUDE_PROTO`) và Zeek (analyzer gắn vào connection)
    làm. A2 loại việc ghép luồng khỏi bài 1. Ba thứ vẫn giữ rủi ro ở mức đọc
    được: (1) port chuẩn thử TRƯỚC nên trên :80 HTTP luôn được xét trước;
    (2) `detect_method="payload"` nói rõ kết luận KHÔNG có port chống lưng;
    (3) `payload_b64` còn nguyên để soi lại.
    """
    return (reply_shape_fits(payload)
            or command_at_start(payload) is not None)


# --- DNS (Phụ lục C, REQ-8, REQ-11.2) ---------------------------------------

def matches_dns(payload: bytes) -> bool:
    """True nếu payload có cấu trúc DNS hợp lệ (Phụ lục C).

    Đây là giao thức DUY NHẤT trong bài không nhận diện được bằng vài byte đầu:
    2 byte đầu của message DNS là transaction ID, tức **cả 65536 giá trị đều
    hợp lệ** — không có chuỗi mở đầu nào như `GET ` của HTTP hay `220 ` của
    SMTP. Vì vậy chữ ký phải là "cấu trúc TỰ NHẤT QUÁN": header ≥ 12 byte,
    QDCOUNT ≥ 1, và toàn bộ phần question giải được trong phạm vi payload.

    Nói cách khác: nhận diện DNS = **thử parse phần question**. Công việc
    byte-level đó nằm trong `dns.question_section_fits()` chứ không viết lại ở
    đây, vì nó thuộc về parser của DNS; registry chỉ cần biết "khớp hay không"
    (NFR-6).

    Hệ quả cần bảo vệ khi vấn đáp: chữ ký này **có thể** nhận nhầm một payload
    UDP ngẫu nhiên đủ ngắn (rủi ro R5 của design). Đó là lý do nó vẫn phải đi
    kèm điều kiện QDCOUNT ≥ 1 và parse trọn question — mỗi điều kiện thêm vào
    làm xác suất trùng hợp nhỏ đi một bậc.
    """
    return question_section_fits(payload)


# --- Registry ---------------------------------------------------------------

# Thứ tự HTTP -> SMTP -> DNS (design §6) là thứ tự thử khi KHÔNG có port nào
# khớp. Cố định trong mã nguồn -> cùng một payload luôn cho cùng một kết quả,
# không phụ thuộc thứ tự lặp của dict hay set (NFR-2).
#
# HTTP và SMTP là hai dòng TCP nằm cạnh nhau, nên câu hỏi tự nhiên là "payload
# nào khớp cả hai?" — câu trả lời là KHÔNG CÓ: chữ ký HTTP mở đầu bằng chữ
# ("GET " / "HTTP/1."), hai chữ ký SMTP mở đầu bằng một trong 10 lệnh hoặc bằng
# ba chữ số, và không lệnh nào trong Phụ lục C trùng với một method HTTP. Vậy
# thứ tự ở đây không đổi được kết quả của bất kỳ payload nào; nó vẫn phải cố
# định vì tính tất định không được dựa vào một lập luận có thể sai khi bài sau
# thêm giao thức.
#
# Thêm SMTP vào đây là TOÀN BỘ việc phải làm để pipeline parse được SMTP:
# pipeline lấy hàm parse qua `app_proto_by_name()`, nên không có chỗ nào khác
# phải sửa — đúng NFR-6, và `http.py`/`dns.py` không bị đụng tới.
APP_PROTOCOLS = (
    AppProto(name="HTTP", transport="TCP", ports=(80,), matches=matches_http,
             parse=parse_http),
    AppProto(name="SMTP", transport="TCP", ports=(25,), matches=matches_smtp,
             parse=parse_smtp),
    AppProto(name="DNS", transport="UDP", ports=(53,), matches=matches_dns,
             parse=parse_dns),
)


def app_proto_by_name(name: str) -> AppProto | None:
    """Tra ngược tên -> dòng registry, để pipeline lấy được hàm parse.

    detect() chỉ trả về TÊN (design §5.3) chứ không trả về cả object: event là
    dữ liệu JSON thuần, nên thứ đi qua ranh giới phải là chuỗi. Việc tra ngược
    đặt ở đây vì registry là của detector — pipeline không được giữ bảng riêng,
    nếu không thêm một giao thức sẽ phải sửa hai chỗ (NFR-6).
    """
    for proto in APP_PROTOCOLS:
        if proto.name == name:
            return proto
    return None


def detect(transport: str, sport: int, dport: int, payload: bytes) -> Detection:
    """Thuật toán 4 bước của design §6.

    Chia ứng viên thành hai nhóm rồi thử lần lượt (chứ không sắp xếp bằng
    sorted(key=...)): hai nhóm cũng chính là hai giá trị của detect_method, nên
    khi một ứng viên khớp thì phương pháp nhận diện đã có sẵn, không phải kiểm
    lại port lần nữa.
    """
    # Bước 1 — REQ-15.4. Kiểm trước vòng lặp: mọi chữ ký đều cần ít nhất một
    # byte, và "không có dữ liệu" khác "có dữ liệu nhưng không hiểu" (UNKNOWN).
    if not payload:
        return Detection(None, None)

    # Bước 2 — ứng viên phải cùng transport: chữ ký DNS chỉ có nghĩa trên một
    # datagram UDP; áp nó lên payload TCP là so sánh hai thứ khác loại.
    port_matched, others = [], []
    for proto in APP_PROTOCOLS:
        if proto.transport != transport:
            continue
        # Xét CẢ HAI port: một phiên HTTP có request (dport=80) và response
        # (sport=80); chỉ xét dport thì mọi response đều rơi xuống nhóm sau.
        if sport in proto.ports or dport in proto.ports:
            port_matched.append(proto)
        else:
            others.append(proto)

    # Bước 3 — payload quyết định kết quả (REQ-10.2). Port khớp mà chữ ký không
    # khớp thì KHÔNG gán: một shell ngược nằm ở port 80 vẫn không phải HTTP.
    for proto in port_matched:
        if proto.matches(payload):
            return Detection(proto.name, "port+payload")
    for proto in others:
        if proto.matches(payload):
            return Detection(proto.name, "payload")     # REQ-11: port lạ

    # Bước 4 — có dữ liệu nhưng không giao thức nào nhận. method để None vì
    # không có phương pháp nào dẫn tới kết luận; UNKNOWN là kết quả của việc
    # thử hết mà trượt, không phải một cách nhận diện.
    return Detection("UNKNOWN", None)
