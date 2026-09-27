"""Tầng transport: parser TCP (REQ-5.1-5.5, Phụ lục A.3, I-4).

Hai chi tiết quyết định parser này đúng hay sai:

1. `data_offset` đếm theo TỪ 4 BYTE, giống IHL của IPv4. Segment của một phiên
   TCP thật gần như luôn có options (MSS, SACK, timestamp, window scale), nên
   giả định header 20 byte sẽ làm payload lệch đúng bằng độ dài options — và
   lệch một cách IM LẶNG: vẫn ra bytes, chỉ là bytes sai (REQ-5.3).
2. Cờ là các BIT trong một byte, không phải một con số. Event ghi cờ thành
   danh sách TÊN theo thứ tự bit cố định để ba packet của một handshake phân
   biệt được chỉ bằng trường này (REQ-5.2, TC-01).
"""
import struct

from ..core.event import b64
from .common import ParseResult, need

TCP_MIN_HEADER_LEN = 20         # data offset = 5 -> 5 * 4 byte
TCP_MIN_DATA_OFFSET = 5         # header không có options
TCP_HEADER_UNIT = 4             # data offset đếm theo từ 4 byte (REQ-5.3)

# "!HHIIBBHHH" = đúng 20 byte của header TCP không options:
#   H  src_port           H  dst_port
#   I  sequence number    I  acknowledgment number
#   B  data offset (4 bit) | reserved (3 bit) | NS (1 bit)
#   B  8 bit cờ
#   H  window             H  checksum          H  urgent pointer
_TCP_HEADER = struct.Struct("!HHIIBBHHH")

# Thứ tự trong tuple này CHÍNH LÀ thứ tự cờ trong event (design §5.4): theo
# giá trị bit tăng dần, khớp thứ tự cờ trong byte thứ 14 của header (RFC 9293).
# Nhờ vậy ["SYN"] rồi ["SYN","ACK"] rồi ["ACK"] đọc ra đúng ba bước handshake,
# và output tất định (NFR-2) vì không phụ thuộc thứ tự lặp của dict hay set.
TCP_FLAGS = (
    (0x01, "FIN"),   # bên gửi không còn dữ liệu -> xin đóng một chiều
    (0x02, "SYN"),   # xin mở kết nối, đồng bộ sequence number
    (0x04, "RST"),   # huỷ kết nối ngay (port đóng trả cái này -> dấu hiệu scan)
    (0x08, "PSH"),   # đẩy dữ liệu lên ứng dụng, không chờ đầy buffer
    (0x10, "ACK"),   # trường acknowledgment number có nghĩa
    (0x20, "URG"),   # trường urgent pointer có nghĩa
    (0x40, "ECE"),   # ECN-Echo
    (0x80, "CWR"),   # Congestion Window Reduced
)


def flag_names(flags: int) -> list:
    """Byte cờ -> ["SYN", "ACK"]. Không cờ nào bật -> [] (NULL scan).

    Trả list chứ không set: JSON không có set, và list giữ thứ tự nên hai event
    cùng bộ cờ luôn cho ra cùng một chuỗi JSON (điều kiện của test_deterministic).
    """
    return [name for bit, name in TCP_FLAGS if flags & bit]


def parse_tcp(data: bytes) -> ParseResult:
    """Payload của IPv4 -> ParseResult của tầng transport.

    next_proto để None (không như IPv4): không có con số nào trong header TCP
    nói payload là giao thức gì — port chỉ là gợi ý, nên việc chọn parser tầng
    ứng dụng thuộc về detector (ADR-5), không thuộc parser này.
    """
    if not need(data, 0, TCP_MIN_HEADER_LEN):
        return ParseResult(
            error=f"tcp header needs {TCP_MIN_HEADER_LEN} bytes, got {len(data)}"
        )

    (src_port, dst_port, seq, ack, offset_reserved, flags,
     window, _checksum, _urgent) = _TCP_HEADER.unpack_from(data, 0)

    # Nửa cao của byte 12 là data offset; nửa thấp là reserved + NS, bỏ qua.
    data_offset = offset_reserved >> 4
    header_len = data_offset * TCP_HEADER_UNIT

    # Dựng phần không phụ thuộc payload trước, để ca lỗi data offset vẫn có
    # đủ port và cờ ghi vào event (REQ-14.1) — port và cờ là thứ một IDS cần
    # nhất khi soi một segment hỏng (vd phát hiện scan bằng cờ lạ).
    fields = {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,          # đơn vị 4 byte, KHÔNG phải byte
        "flags": flag_names(flags),
        "window": window,
        "payload_len": 0,
        "payload_b64": "",
    }

    if data_offset < TCP_MIN_DATA_OFFSET:
        # header_len < 20 -> payload sẽ bắt đầu GIỮA header, tức parser sẽ đưa
        # chính các byte header lên tầng ứng dụng (REQ-5.5).
        return ParseResult(
            fields=fields,
            error=f"tcp data_offset={data_offset} is below minimum "
                  f"{TCP_MIN_DATA_OFFSET} (header would be {header_len} bytes)",
        )

    if not need(data, 0, header_len):
        # Khai có options nhưng segment không đủ dài chứa chúng. Không cắt ngắn
        # im lặng: data[60:] trên segment 20 byte cho b"" chứ không báo lỗi.
        return ParseResult(
            fields=fields,
            error=f"tcp header declares {header_len} bytes "
                  f"(data_offset={data_offset}), got {len(data)}",
        )

    payload = data[header_len:]
    fields["payload_len"] = len(payload)
    # I-4: base64 chuẩn -> giải mã ngược ra đúng bytes gốc. payload thật chứa
    # byte không hợp lệ trong UTF-8 nên không thể ghi thẳng vào JSON.
    fields["payload_b64"] = b64(payload)
    return ParseResult(fields=fields, payload=payload)
