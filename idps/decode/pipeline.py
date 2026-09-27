"""process_frame() — điểm vào duy nhất của pipeline decode (C-4, D1, I-1).

Live và PCAP đều đi qua hàm này, nên hành vi parse ở hai chế độ giống nhau
theo cấu trúc chứ không nhờ kỷ luật khi viết code (REQ-3.2).

Thứ tự stage cố định: Link -> Network -> Transport -> Detector -> App (C-4).
Bài 1 dựng dần: Phase 2 mới có tầng liên kết, T5.4 nối network/transport,
T6.4 nối detector + app parser.
"""
from ..core.event import add_error, compute_status, new_event
from .ethernet import ETHERTYPE_IPV4, link_name, parse_link


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

    # EtherType đã cho biết tầng network là IPv4; khoá "ipv4" còn null cho tới
    # khi T5.4 gọi parse_ipv4(link.payload) tại đúng chỗ này.
    event["network_proto"] = "IPv4"
