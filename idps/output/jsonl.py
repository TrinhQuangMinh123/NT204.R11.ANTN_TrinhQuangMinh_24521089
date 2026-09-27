"""JsonlWriter — ghi mỗi event thành đúng một dòng JSON (REQ-13, ADR-8).

JSON Lines chứ không phải một mảng JSON: mảng chỉ hợp lệ khi đã có dấu `]`
cuối cùng, nên một lần chạy live bị Ctrl+C sẽ để lại file hỏng. Ở dạng này,
mỗi dòng độc lập -> file luôn đọc được kể cả khi tiến trình bị kill, và bài
sau đọc lại bằng vòng lặp `for line in f` mà không cần nạp cả file (C-6).
"""
import json

from ..core.sink import EventSink


class JsonlWriter(EventSink):
    """Mở file ngay trong __init__ để lỗi ghi lộ ra TRƯỚC khi capture bắt đầu.

    REQ-13.4/20.4: chạy 10 phút rồi mới phát hiện không ghi được file là mất
    trắng; main.py vì vậy dựng mọi sink trước khi dựng nguồn.
    """

    def __init__(self, path):
        self.path = str(path)
        # newline="\n": không để Python đổi "\n" thành "\r\n" theo nền tảng,
        # nếu không cùng một PCAP chạy trên hai máy ra hai file khác byte (NFR-2).
        # encoding="ascii": ensure_ascii=True bên dưới đã bảo đảm mọi ký tự đều
        # là ASCII, khai báo ở đây để nếu quy ước đó bị phá thì vỡ ngay tại chỗ
        # chứ không âm thầm ghi ra file nhiều byte lạ.
        self._file = open(self.path, "w", encoding="ascii", newline="\n")

    def handle(self, event: dict) -> None:
        # ensure_ascii=True: mọi ký tự điều khiển và ký tự ngoài ASCII trong dữ
        # liệu packet đều bị escape (\n -> \\n) -> một packet chứa "\n{...}"
        # trong URI vẫn chỉ là một chuỗi nằm trong một dòng (I-3, chống chèn log).
        # separators=(",", ":"): bỏ khoảng trắng thừa, file nhỏ và tất định.
        line = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        self._file.write(line)
        self._file.write("\n")
        # flush từng dòng (ADR-8 phương án A): REQ-1.3 đòi event xuất hiện
        # trong file NGAY trong lúc capture live còn đang chạy, và nếu tiến
        # trình bị SIGKILL thì phần đã ghi vẫn còn.
        self._file.flush()

    def close(self) -> None:
        # close() của Python là idempotent -> Runner gọi lại lần nữa (vd vừa
        # hết file vừa Ctrl+C) cũng không lỗi.
        self._file.close()
