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

Registry `APP_PROTOCOLS` là điểm mở rộng (NFR-6): thêm SMTP/DNS ở Phase 9/8 =
thêm một hàm `matches_*` ngay cạnh đây + một dòng trong tuple. Không sửa
`detect()`, không sửa parser của giao thức khác.
"""
from dataclasses import dataclass
from typing import Callable

from .common import ParseResult


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


# --- Registry ---------------------------------------------------------------

# Thứ tự HTTP -> SMTP -> DNS (design §6) là thứ tự thử khi KHÔNG có port nào
# khớp. Cố định trong mã nguồn -> cùng một payload luôn cho cùng một kết quả,
# không phụ thuộc thứ tự lặp của dict hay set (NFR-2).
APP_PROTOCOLS = (
    AppProto(name="HTTP", transport="TCP", ports=(80,), matches=matches_http),
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
