"""Hợp đồng dùng chung giữa các stage của pipeline (design §5.2, ADR-4).

Không import parser nào: mọi parser import file này, nên nếu file này import
ngược lại sẽ thành vòng tròn.
"""
from dataclasses import dataclass, field


@dataclass
class ParseResult:
    """Kết quả của một tầng parse.

    error KHÔNG phải exception (ADR-4): packet hỏng là dữ liệu bình thường đối
    với một IDS đặt trước mặt attacker, không phải sự kiện bất thường của
    chương trình. Parser mô tả lỗi rồi trả về; pipeline là nơi quyết định có
    đi tiếp lên tầng trên hay không.

    fields và error được phép khác rỗng CÙNG LÚC: DNS parse được 1 answer rồi
    phát hiện ANCOUNT khai 5 -> giữ answer đã có, kèm lý do lỗi (REQ-8.5).
    """

    # Các trường của riêng tầng này, chỉ kiểu JSON -> ghép thẳng vào event
    fields: dict = field(default_factory=dict)
    # Bytes dành cho tầng trên (b"" nếu tầng này không có payload)
    payload: bytes = b""
    # Gợi ý chọn parser tầng trên: EtherType (link), protocol number (IPv4).
    # None ở transport/app vì ở đó payload do detector quyết định, không do
    # một con số trong header.
    next_proto: int | None = None
    # None = không lỗi. Khác None = pipeline ghi lỗi và dừng đi lên.
    error: str | None = None


def need(data: bytes, offset: int, n: int) -> bool:
    """True nếu đọc n byte từ vị trí offset vẫn nằm trong data.

    Mọi parser gọi hàm này TRƯỚC khi đọc (I-5). Lý do: hai cách đọc bytes của
    Python đều không dùng được thẳng cho dữ liệu do kẻ tấn công cung cấp.
      data[offset:offset + n]      -> cắt ngắn im lặng, parse ra số sai
      struct.unpack_from(...)      -> ném struct.error, biến lỗi dữ liệu
                                      thành ngoại lệ (ADR-4 không muốn thế)

    offset < 0 cũng trả False: một offset âm do tính nhầm (vd IHL*4 - 20 khi
    IHL < 5) sẽ khiến slice của Python đếm ngược từ cuối buffer và parse ra
    dữ liệu của tầng khác thay vì báo lỗi.
    """
    if offset < 0 or n < 0:
        return False
    return len(data) - offset >= n
