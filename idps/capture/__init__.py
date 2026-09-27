"""Tầng capture — nơi DUY NHẤT của dự án được phép import Scapy (I-9, ADR-2).

Chỉ chứa kiểu lỗi dùng chung cho mọi nguồn packet. CỐ Ý không import pcap.py
hay live.py ở đây: main.py phải bắt được SourceError từ trước khi biết lần
chạy này dùng chế độ nào, mà nếu __init__ kéo theo hai module kia thì chỉ để
lấy một class lỗi đã phải nạp cả Scapy.
"""


class SourceError(Exception):
    """Nguồn packet không dùng được (design §6, §8.2).

    File không tồn tại, sai magic, là PCAPNG, interface không có, thiếu
    NET_RAW... — mọi lý do khiến cả lần chạy mất nghĩa.

    Đây là ngoại lệ, khác hẳn ParseResult.error của tầng decode (ADR-4):
    packet hỏng là dữ liệu bình thường với một IDS và phải thành một event,
    còn "không mở được nguồn" thì không có event nào để ghi -> dừng ngay và
    exit 1 (REQ-2.4, REQ-1.4, REQ-1.5).
    """
