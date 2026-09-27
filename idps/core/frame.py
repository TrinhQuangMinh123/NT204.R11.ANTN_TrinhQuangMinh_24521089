"""RawFrame — hợp đồng giữa tầng capture và pipeline decode (design §5.1).

Đây là kiểu dữ liệu DUY NHẤT mà idps/capture/ được phép trả ra. Mọi trường đều
là kiểu dựng sẵn của Python, nên object của thư viện capture (Scapy) không có
chỗ nào để bám theo sang tầng decode (C-6, I-9).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class RawFrame:
    """Một frame thô, kèm siêu dữ liệu về lần thu nhận nó.

    frozen=True: mọi phép gán thuộc tính đều ném FrozenInstanceError (một
    lớp con của AttributeError), kể cả gán một tên chưa có. Frame là bản ghi
    của cái đã xảy ra trên dây — nếu một parser sửa được data hay ts_sec thì
    các tầng chạy sau nó đọc phải dữ liệu khác với dữ liệu thật đã bắt, còn
    gắn thêm frame.ghi_chu = ... sẽ làm hợp đồng §5.1 phình ra ngoài bảng.

    Không dùng slots=True: trên CPython 3.12, frozen + slots sinh ra một
    __setattr__ tham chiếu lớp cũ, nên gán một tên LẠ ném TypeError thay vì
    FrozenInstanceError. frozen một mình đã chặn đủ cả hai trường hợp.
    """

    data: bytes      # bytes thu được, bắt đầu từ header tầng liên kết
    ts_sec: int      # giây kể từ epoch Unix (UTC)
    ts_usec: int     # micro giây trong giây đó
    wire_len: int    # độ dài gốc trên dây (PCAP: orig_len; live: len(data))
    linktype: int    # mã LINKTYPE (1 = Ethernet), Phụ lục D
    source: str      # "live" hoặc "pcap"
    # Bản ghi PCAP khai báo incl_len byte nhưng file hết sớm hơn (file bị cắt
    # giữa chừng). Mặc định False nên phải nằm cuối; thứ tự các trường còn lại
    # giữ đúng bảng design §5.1.
    truncated: bool = False
