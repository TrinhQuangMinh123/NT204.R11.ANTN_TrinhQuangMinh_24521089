"""PcapSource — đọc file PCAP cổ điển thành luồng RawFrame (REQ-2, ADR-2).

Scapy ở đây chỉ là "ống dẫn": RawPcapReader trả về bytes thô + siêu dữ liệu
của bản ghi, KHÔNG dissect. Không một object Scapy nào đi ra khỏi file này —
thứ trả ra là RawFrame gồm toàn kiểu dựng sẵn (C-5, C-6, D2).
"""
from scapy.error import Scapy_Exception
from scapy.utils import RawPcapReader

from ..core.frame import RawFrame
from . import SourceError

# 4 byte đầu file. PCAP ghi số theo THỨ TỰ BYTE CỦA MÁY ĐÃ TẠO FILE, nên cùng
# một giá trị 0xa1b2c3d4 xuất hiện dưới hai dạng — người đọc so byte thô để
# biết phải đọc phần còn lại theo little hay big endian.
# Giá trị trong bảng = file có dùng nano giây hay không: bản PCAP nano giây
# (0xa1b23c4d) có cấu trúc y hệt, chỉ khác ở chỗ trường ts thứ hai là nano
# giây chứ không phải micro giây.
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": False,   # micro giây, little-endian
    b"\xa1\xb2\xc3\xd4": False,   # micro giây, big-endian
    b"\x4d\x3c\xb2\xa1": True,    # nano giây,  little-endian
    b"\xa1\xb2\x3c\x4d": True,    # nano giây,  big-endian
}

# Block type Section Header Block của PCAPNG. Tách riêng khỏi nhánh "magic lạ"
# để thông báo lỗi nói đúng bệnh: file hợp lệ nhưng sai ĐỊNH DẠNG (Phụ lục D).
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_NANO_PER_USEC = 1000


class PcapSource:
    """Nguồn packet đọc từ file. `PcapSource(path).frames()` -> Iterator[RawFrame].

    Mọi kiểm tra định dạng nằm trong __init__ chứ không trong frames(), vì
    frames() là hàm generator: thân hàm chỉ chạy ở lần next() đầu tiên, nên
    nếu kiểm tra ở đó thì main.py đã mở xong file output và "bắt đầu chạy"
    rồi mới biết file vào không dùng được. Hợp đồng ở design §6 là nguồn phải
    ném TRƯỚC frame đầu tiên.
    """

    def __init__(self, path):
        self.path = str(path)
        magic = self._read_magic()
        if magic == _PCAPNG_MAGIC:
            # REQ-17.4. Phải tự chặn ở đây: đưa file này cho Scapy thì
            # PcapReader_metaclass lặng lẽ chuyển sang RawPcapNgReader và
            # chương trình chạy tiếp như không có gì (ADR-2).
            raise SourceError(f"PCAPNG is not supported, only classic pcap: {self.path}")
        if magic not in _PCAP_MAGICS:
            raise SourceError(f"not a pcap file (magic {magic.hex()!r}): {self.path}")
        self.nano = _PCAP_MAGICS[magic]

    def _read_magic(self) -> bytes:
        """4 byte đầu file. File ngắn hơn 4 byte -> trả về đúng số byte có."""
        try:
            with open(self.path, "rb") as f:
                return f.read(4)
        except OSError as exc:
            # REQ-2.4: không tồn tại, là thư mục, không có quyền đọc...
            # str(exc) đã chứa errno và tên file -> thông báo cho người chạy
            # đủ để sửa mà không phải đoán.
            raise SourceError(f"cannot open pcap file: {exc}") from exc

    def frames(self):
        """Lần lượt từng bản ghi trong file, đúng thứ tự ghi (REQ-2.1)."""
        try:
            reader = RawPcapReader(self.path)
        except (Scapy_Exception, OSError, EOFError) as exc:
            # Magic đúng nhưng phần còn lại của global header (20 byte) thiếu:
            # file bị cắt ngay ở đầu. Đổi sang SourceError để main.py chỉ phải
            # biết một loại lỗi nguồn duy nhất.
            raise SourceError(f"cannot read pcap file {self.path}: {exc}") from exc

        with reader:
            # Linktype nằm trong global header, áp dụng cho MỌI bản ghi của
            # file (Phụ lục D) — đọc một lần, không đọc lại trong vòng lặp.
            linktype = reader.linktype
            for data, meta in reader:
                yield RawFrame(
                    data=data,
                    ts_sec=meta.sec,
                    # File nano giây: trường thứ hai là nano giây. Chia số
                    # nguyên (làm tròn xuống) chứ không round(): RawFrame quy
                    # định 0 <= ts_usec < 1_000_000, mà round(999_999_999/1000)
                    # = 1_000_000 sẽ phá luôn giao ước đó ở packet cuối giây.
                    ts_usec=meta.usec // _NANO_PER_USEC if self.nano else meta.usec,
                    # orig_len: độ dài gốc trên dây. Khác caplen khi tcpdump
                    # chạy với snaplen nhỏ hơn packet — đó KHÔNG phải lỗi.
                    wire_len=meta.wirelen,
                    linktype=linktype,
                    source="pcap",
                    # REQ-2.5: bản ghi khai incl_len byte nhưng file hết sớm
                    # hơn. Scapy trả về phần đọc được và không báo gì, nên
                    # phải tự so; pipeline sẽ ghi lỗi "capture" rồi vẫn parse
                    # phần có. (Cũng bắt luôn ca incl_len > 65535 = MTU của
                    # Scapy: ta không nhận đủ số byte đã khai, đúng nghĩa cụt.)
                    truncated=len(data) < meta.caplen,
                )
