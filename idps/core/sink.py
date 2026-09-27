"""EventSink — điểm gắn của mọi module phía sau pipeline (REQ-20, ADR-12, D9).

Nằm trong core/ nên không import decode/output (I-9): một module bài sau chỉ
cần biết "event là dict đúng schema §5.4" là cài được sink, không phải kéo
theo parser.

Bài 1 mới có một cài đặt là JsonlWriter. Bài sau (trích xuất đặc trưng, phát
hiện, cảnh báo, chặn) thêm sink mới và nối vào danh sách sinks trong main.py —
không sửa capture, decode hay Runner (NFR-9).
"""


class EventSink:
    """Nơi nhận event của một lần chạy, theo đúng thứ tự packet_id (REQ-20.1).

    Dùng lớp cơ sở chứ không chỉ "quy ước có hai method" để chỗ gắn module là
    một cái tên tra được trong mã nguồn, và để mọi sink thừa hưởng close()
    rỗng — phần lớn module phía sau (vd bộ đếm) không có tài nguyên để đóng.
    """

    def handle(self, event: dict) -> None:
        """Nhận một event. Sink có quyền giữ trạng thái giữa các lần gọi
        (bảng flow của bài trích xuất đặc trưng)."""
        raise NotImplementedError

    def close(self) -> None:
        """Lần chạy kết thúc (hết file PCAP, Ctrl+C hoặc SIGTERM).

        Runner gọi trong finally và gọi TRƯỚC khi in thống kê (REQ-20.3), nên
        sink được bảo đảm có cơ hội xả bộ đệm dù lần chạy bị cắt ngang.
        """
