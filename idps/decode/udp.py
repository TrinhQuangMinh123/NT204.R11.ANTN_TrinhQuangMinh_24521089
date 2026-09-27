"""Tầng transport: parser UDP (REQ-6.1, 6.2, Phụ lục A.4, I-4).

Header UDP chỉ có 8 byte và không có options, nên không có ca "độ dài header
thay đổi" như IHL của IPv4 hay data offset của TCP. Đổi lại nó có một ca lỗi
riêng: UDP là giao thức DUY NHẤT trong bài tự khai độ dài của chính mình
(trường `length`, tính CẢ 8 byte header). TCP không có trường nào như vậy —
độ dài payload TCP suy ra từ `total_length` của IPv4. Vì tự khai nên con số
này có thể không khớp dữ liệu thật, và đó chính là REQ-6.2.
"""
import struct

from ..core.event import b64
from .common import ParseResult, need

UDP_HEADER_LEN = 8              # 2 src + 2 dst + 2 length + 2 checksum

# "!HHHH" = src_port, dst_port, length, checksum.
_UDP_HEADER = struct.Struct("!HHHH")


def parse_udp(data: bytes) -> ParseResult:
    """Payload của IPv4 -> ParseResult của tầng transport.

    KHÔNG kiểm checksum: với IPv4, checksum của UDP là TUỲ CHỌN — giá trị 0
    nghĩa là bên gửi không tính (RFC 768). Một datagram checksum 0 là hợp lệ,
    nên kiểm sẽ báo sai; cộng thêm lý do TX checksum offload như ở IPv4.

    next_proto để None: giống TCP, port chỉ là gợi ý cho detector (ADR-5).
    """
    if not need(data, 0, UDP_HEADER_LEN):
        return ParseResult(
            error=f"udp header needs {UDP_HEADER_LEN} bytes, got {len(data)}"
        )

    src_port, dst_port, length, _checksum = _UDP_HEADER.unpack_from(data, 0)

    fields = {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,                    # tính CẢ 8 byte header
        "payload_len": 0,
        "payload_b64": "",
    }

    if length < UDP_HEADER_LEN:
        # Tự mâu thuẫn: length tính cả header nên không thể nhỏ hơn 8.
        return ParseResult(
            fields=fields,
            error=f"udp length={length} is smaller than header "
                  f"length {UDP_HEADER_LEN}",
        )

    if length != len(data):
        # So BẰNG chứ không chỉ so >: IPv4 đã cắt data theo total_length trước
        # khi giao xuống đây, nên len(data) là độ dài datagram thật. length
        # nhỏ hơn cũng là hỏng — nghĩa là trong packet còn byte không ai nhận,
        # thường là dấu hiệu dữ liệu bị dựng bằng tay (REQ-6.2).
        return ParseResult(
            fields=fields,
            error=f"udp length={length} does not match available "
                  f"{len(data)} bytes",
        )

    payload = data[UDP_HEADER_LEN:length]
    fields["payload_len"] = len(payload)
    fields["payload_b64"] = b64(payload)     # I-4
    return ParseResult(fields=fields, payload=payload)
