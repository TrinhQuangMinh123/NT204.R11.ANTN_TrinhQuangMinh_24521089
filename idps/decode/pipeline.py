"""process_frame() — điểm vào duy nhất của pipeline decode (C-4, D1, I-1).

Live và PCAP đều đi qua hàm này, nên hành vi parse ở hai chế độ giống nhau
theo cấu trúc chứ không nhờ kỷ luật khi viết code (REQ-3.2).

Thứ tự stage cố định: Link -> Network -> Transport -> Detector -> App (C-4).
Bài 1 dựng dần: Phase 2 mới có tầng liên kết, T5.4 nối network/transport,
T6.4 nối detector + app parser.
"""
from ..core.event import add_error, compute_status, new_event
from .detector import app_proto_by_name, detect
from .ethernet import ETHERTYPE_IPV4, link_name, parse_link
from .ipv4 import PROMOTED_FIELDS, PROTO_TCP, PROTO_UDP, parse_ipv4
from .tcp import parse_tcp
from .udp import parse_udp

# Bảng tra IP protocol number -> (tên ghi vào event, hàm parse), cùng hình dạng
# với LINK_PARSERS của tầng liên kết. Khoá của event ("tcp"/"udp") là tên này
# viết thường, nên thêm một giao thức transport = thêm MỘT dòng ở đây (NFR-8).
TRANSPORT_PARSERS = {
    PROTO_TCP: ("TCP", parse_tcp),
    PROTO_UDP: ("UDP", parse_udp),
}


def process_frame(frame, packet_id: int) -> dict:
    """RawFrame -> event đầy đủ khoá. KHÔNG BAO GIỜ ném ngoại lệ (I-1).

    new_event() nằm ngoài try vì nó chỉ đọc siêu dữ liệu số do chính tầng
    capture dựng (packet_id, ts, độ dài, linktype); mọi byte do kẻ tấn công
    điều khiển đều nằm trong _decode().

    except Exception ở đây là lưới an toàn cho BUG CỦA CHÍNH MÌNH, không phải
    cách xử lý packet hỏng (ADR-4): packet hỏng đã đi đường ParseResult.error.
    Vì vậy lỗi "internal" xuất hiện = một parser còn thiếu một lần kiểm tra
    biên, và NFR-1 đo đúng bằng số lỗi internal trên bộ packet hỏng = 0.
    """
    event = new_event(frame, packet_id)
    try:
        _decode(frame, event)
    except Exception as exc:  # noqa: BLE001 - lưới an toàn có chủ đích (REQ-15.3)
        # Giữ tên lớp ngoại lệ: đọc log là biết ngay lỗi loại gì mà không cần
        # chạy lại. Các trường đã điền được trước khi ném vẫn nằm trong event.
        add_error(event, "internal", f"{type(exc).__name__}: {exc}")
    # Tính sau except -> một bug bị bắt vẫn cho ra event malformed hợp lệ thay
    # vì làm mất packet.
    event["status"] = compute_status(event)
    return event


def _decode(frame, event: dict) -> None:
    """Đi qua từng tầng, điền vào event tại chỗ. return = dừng đi lên.

    Quy tắc §4.2: một tầng báo lỗi -> ghi lỗi và dừng, các trường tầng dưới
    đã parse được giữ nguyên (REQ-14.1, 15.2).
    """
    if frame.truncated:
        # Bản ghi PCAP khai nhiều byte hơn số byte thật có trong file. Ghi lỗi
        # nhưng VẪN parse tiếp phần đọc được (REQ-2.5) — phần đầu frame thường
        # còn nguyên, ném đi là mất thông tin không cần thiết.
        add_error(event, "capture", "truncated record")

    link = parse_link(frame.linktype, frame.data)
    if link is None:
        # Chưa hỗ trợ linktype này -> unknown, không phải malformed (REQ-17.2)
        event["link_proto"] = "UNKNOWN"
        return

    event["link_proto"] = link_name(frame.linktype)
    if link.fields:
        event["ethernet"] = link.fields
    if link.error:
        add_error(event, "link", link.error)
        return

    if link.next_proto != ETHERTYPE_IPV4:
        # ARP, IPv6, VLAN... : frame đọc xong, tầng trên thì chưa hỗ trợ
        # (REQ-17.3). Trường ethernet ở trên vẫn giữ nguyên.
        event["network_proto"] = "UNKNOWN"
        return

    event["network_proto"] = "IPv4"

    net = parse_ipv4(link.payload)
    if net.fields:
        # src_ip/dst_ip đi lên 5-tuple ở top-level của event (Phụ lục A.1) và
        # được LẤY RA khỏi khoá "ipv4", để cùng một giá trị không bị ghi hai
        # lần trong một dòng JSON — tập khoá của "ipv4" đúng như design §5.4.
        ipv4_fields = net.fields
        for key in PROMOTED_FIELDS:
            event[key] = ipv4_fields.pop(key, None)
        event["ipv4"] = ipv4_fields
    if net.error:
        add_error(event, "ipv4", net.error)
        return

    if event["ipv4"]["fragment_offset"] != 0:
        # REQ-4.4: từ mảnh thứ hai trở đi, byte đầu tiên của payload là DỮ LIỆU
        # của tầng trên chứ không phải header TCP/UDP. Parse tiếp vẫn "thành
        # công" nhưng cho ra port, cờ và sequence number bịa ra từ dữ liệu —
        # sai mà không có lỗi nào báo, nên phải dừng ở đây. Event vẫn nói rõ
        # đây là mảnh qua ipv4.is_fragment và ipv4.fragment_offset.
        return

    entry = TRANSPORT_PARSERS.get(net.next_proto)
    if entry is None:
        # ICMP, IGMP, ESP...: IPv4 đã parse xong, tầng transport thì bài 1 chưa
        # hỗ trợ -> unknown chứ không phải malformed (cùng lý lẽ với REQ-17.2).
        # Các trường IPv4 và src_ip/dst_ip ở trên vẫn giữ nguyên (REQ-14.1).
        event["transport_proto"] = "UNKNOWN"
        return

    name, parse_transport = entry
    # Gán tên TRƯỚC khi parse: protocol number đã xác định đây là TCP, kể cả
    # khi header TCP hỏng thì nó vẫn là một segment TCP hỏng.
    event["transport_proto"] = name
    transport = parse_transport(net.payload)
    if transport.fields:
        event[name.lower()] = transport.fields
        event["src_port"] = transport.fields["src_port"]
        event["dst_port"] = transport.fields["dst_port"]
    if transport.error:
        # Tên tầng là tên giao thức ("tcp"/"udp") để đọc errors[].layer là biết
        # ngay parser nào phát hiện lỗi (REQ-15.2, V5.2).
        add_error(event, name.lower(), transport.error)
        return

    _decode_app(event, name, transport.payload)


def _decode_app(event: dict, transport_name: str, payload: bytes) -> None:
    """Tầng ứng dụng: nhận diện trước, parse sau (ADR-5, REQ-10.4, 15.4).

    Hai bước tách rời nhau vì chúng trả lời hai câu hỏi khác nhau, và câu thứ
    nhất có thể trả lời được trong khi câu thứ hai thất bại: detect() nói "đây
    là HTTP" dựa vào 4 byte đầu, parse_http() có thể vẫn báo lỗi ở header thứ 5.
    Khi đó event vừa có app_proto="HTTP" vừa có errors[].layer="http" — đúng
    điều một IDS cần: biết giao thức gì để áp luật nào, và biết nó hỏng ở đâu.
    """
    detection = detect(transport_name, event["src_port"], event["dst_port"],
                       payload)
    # Ghi kết quả nhận diện TRƯỚC khi parse: kể cả parser báo lỗi thì event vẫn
    # nói được đây là giao thức gì và đã nhận diện bằng cách nào (REQ-10.4).
    event["app_proto"] = detection.app_proto
    event["detect_method"] = detection.method

    if detection.app_proto is None or detection.app_proto == "UNKNOWN":
        # ADR-14: app = null ở cả hai ca. None = payload rỗng (REQ-15.4, không
        # phải lỗi); "UNKNOWN" = có dữ liệu nhưng không chữ ký nào khớp — cũng
        # không phải lỗi, chỉ là bài 1 mới có ba giao thức. Vì vậy KHÔNG gọi
        # add_error, và status vẫn là "ok" (app_proto không nằm trong danh sách
        # _UNKNOWN_KEYS của event.py).
        return

    # detect() chỉ trả về tên lấy từ chính APP_PROTOCOLS, nên tra ngược luôn ra
    # một dòng registry — không cần kiểm None ở đây (NFR-6).
    proto = app_proto_by_name(detection.app_proto)
    if proto.parse is None:
        # Đã nhận ra tên nhưng chưa có parser (AppProto.parse mặc định None).
        # app giữ null; app_proto vẫn ghi để thống kê và để luật theo port/proto
        # dùng được ngay. Phase 8/9 điền parser cho DNS/SMTP là hết ca này.
        return

    app = proto.parse(payload)
    if app.fields:
        event["app"] = app.fields
    if app.error:
        # Tên tầng là tên giao thức viết thường ("http"), cùng quy ước với
        # "tcp"/"udp" ở tầng transport -> đọc errors[].layer là biết parser nào
        # phát hiện lỗi (REQ-15.2, V6.2).
        add_error(event, detection.app_proto.lower(), app.error)
