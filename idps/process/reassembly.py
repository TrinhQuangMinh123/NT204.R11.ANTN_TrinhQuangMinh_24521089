"""Bộ đệm gom byte pha DATA của SMTP — một bộ đệm cho MỘT flow (REQ-40, ADR-26).

Thư dài hơn một packet nên nội dung đến theo từng mảnh. File này chỉ lo phần
"nối mảnh và cắt thành từng thư": không biết gì về flow, event hay MIME — việc
giải mã nội dung thư là của `codecs.mime_decode` (REQ-40.8), việc nhận biết lúc
nào vào/ra pha DATA là của FlowTracker (T4.2).

Không sắp xếp lại segment và không bù khoảng trống (REQ-40.7): byte đến thế nào
nối thế ấy.
"""

_END_OF_DATA = b"\r\n.\r\n"       # dòng chỉ có một dấu chấm (RFC 5321 §4.1.1.4)
_EMPTY_MAIL_END = b".\r\n"        # thư rỗng: không có "\r\n" đứng trước dấu chấm
_STUFFED = b"\r\n.."              # dòng nội dung bắt đầu bằng "." bị người gửi chèn thêm "."
_UNSTUFFED = b"\r\n."


def _unstuff(mail):
    """Gỡ dot-stuffing (RFC 5321 §4.5.2): `\\r\\n..` → `\\r\\n.`.

    Người gửi chèn thêm một "." vào dòng nào bắt đầu bằng "." để dòng nội dung
    không bị nhầm với dấu kết thúc. Không gỡ thì nội dung thư sai đúng chỗ đó.
    Dòng ĐẦU của thư không có "\\r\\n" đứng trước, nên ghép "\\r\\n" vào rồi cắt đi.
    """
    return (b"\r\n" + mail).replace(_STUFFED, _UNSTUFFED)[2:]


class MailBuffer:
    """Nối byte, cắt từng thư khi gặp dấu kết thúc, giữ ngân sách kích thước.

    Ngân sách tính CẢ bộ đệm lẫn tổng kích thước các thư đã cắt ra (REQ-40.4):
    nếu chỉ tính bộ đệm thì một kết nối gửi liên tục nhiều thư nhỏ vẫn làm flow
    giữ bộ nhớ không giới hạn mà bộ đệm chưa bao giờ đầy.
    """

    def __init__(self, limit):
        self.limit = limit
        self._buffer = bytearray()
        self._emitted = 0            # tổng byte các thư đã trả về qua feed()
        self.stopped = False         # đã chạm ngân sách → bỏ mọi byte đến sau
        self.reasons = []

    @property
    def buffered(self):
        """Số byte đang nằm trong bộ đệm — thứ FlowTracker cộng lại để so ngân sách tổng."""
        return len(self._buffer)

    def feed(self, payload):
        """Nối `payload`, trả danh sách các thư ĐÃ ĐỦ dấu kết thúc (đã gỡ dot-stuffing).

        Một lần `feed` có thể trả 0, 1 hoặc nhiều thư (pipelining). Phần chưa đủ
        dấu kết thúc ở lại bộ đệm cho lần sau, hoặc lấy ra bằng `flush()`.
        """
        if self.stopped:
            return []
        room = self.limit - self._emitted - len(self._buffer)
        if len(payload) > room:
            # Chỉ nhận phần vừa chỗ để bộ đệm không BAO GIỜ vượt ngân sách (I-19),
            # chứ không nhận hết rồi mới cắt.
            payload = payload[:max(room, 0)]
            self.stopped = True
            self.reasons.append(f"reassembly_limit={self.limit}")
        scan_from = max(len(self._buffer) - len(_END_OF_DATA) + 1, 0)
        self._buffer += payload
        return self._cut_mails(scan_from)

    def flush(self):
        """Trả phần còn lại chưa thấy dấu kết thúc (rỗng thì trả []), và dọn bộ đệm.

        Gọi khi flow đóng hoặc khi `stopped`: dữ liệu đã gom không bị bỏ đi (REQ-40.3);
        người gọi biết nó là thư dở dang vì không đi qua `feed`.
        """
        if not self._buffer:
            return []
        rest = _unstuff(bytes(self._buffer))
        self._buffer.clear()
        self._emitted += len(rest)
        return [rest]

    def _cut_mails(self, scan_from):
        """Cắt mọi thư đã đủ dấu kết thúc khỏi đầu bộ đệm.

        `scan_from` để khỏi quét lại phần cũ: dấu kết thúc dài 5 byte nên có thể
        bắt đầu tối đa 4 byte trước chỗ mảnh mới được nối.
        """
        mails = []
        while True:
            if self._buffer.startswith(_EMPTY_MAIL_END):
                end, mail = len(_EMPTY_MAIL_END), b""
            else:
                at = self._buffer.find(_END_OF_DATA, scan_from)
                if at < 0:
                    return mails
                end, mail = at + len(_END_OF_DATA), _unstuff(bytes(self._buffer[:at]))
            del self._buffer[:end]
            self._emitted += len(mail)
            mails.append(mail)
            scan_from = 0            # bộ đệm đã đổi đầu → thư kế tiếp quét từ đầu
