"""Runner — vòng lặp chính DUY NHẤT của chương trình (ADR-12, REQ-20).

Viết một lần ở bài 1. Bài sau thêm module (trích xuất đặc trưng, phát hiện,
cảnh báo, chặn) bằng cách thêm một EventSink vào danh sách `sinks` trong
main.py, không đụng vào file này, cũng không đụng capture/decode (NFR-9).
"""
from .stats import Stats


class Runner:
    """Lấy frame từ nguồn -> đánh số -> decode -> phát cho mọi sink -> đếm.

    `decode` được TIÊM VÀO chứ không import sẵn, vì runner.py nằm trong core/
    mà core/ không được phụ thuộc idps/decode/ (I-9). Ràng buộc đó có lý do
    thật: bài sau đọc lại events.jsonl rồi cho chạy qua đúng chuỗi sink này
    mà không cần bộ parser nào; lúc ấy `decode` là một hàm khác. Ai nối dây
    là việc của main.py.
    """

    def __init__(self, source, sinks, decode):
        self.source = source
        # Chụp lại danh sách: người gọi sửa list của họ sau đó cũng không làm
        # đổi thứ tự phát event giữa chừng (REQ-20.1).
        self.sinks = list(sinks)
        self.decode = decode
        # Là thuộc tính chứ không phải biến cục bộ: khi Ctrl+C cắt ngang,
        # run() không kịp return nhưng main.py vẫn đọc được số đã đếm để in
        # dòng thống kê (REQ-13.5 vẫn phải đúng ở chế độ live).
        self.stats = Stats()

    def run(self) -> Stats:
        """Chạy tới khi hết nguồn. Ctrl+C/SIGTERM đi xuyên qua, sau finally."""
        try:
            # enumerate(start=1): packet_id 1, 2, 3... theo đúng thứ tự xử lý
            # (REQ-12.3, I-8). Đánh số ở đây chứ không ở tầng capture, để hai
            # nguồn live và pcap không phải tự đếm giống nhau (REQ-3.1).
            for packet_id, frame in enumerate(self.source.frames(), start=1):
                event = self.decode(frame, packet_id)
                self.stats.add(event)
                for sink in self.sinks:
                    # Thứ tự sink cố định theo danh sách -> lần chạy tất định.
                    sink.handle(event)
        finally:
            # finally chứ không phải cuối hàm: hết file, lỗi nguồn giữa chừng
            # và Ctrl+C đều phải đi qua đây, nếu không thì dòng cuối còn trong
            # bộ đệm của sink sẽ mất (REQ-20.3, REQ-1.6).
            for sink in self.sinks:
                sink.close()
        return self.stats
