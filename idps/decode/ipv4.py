"""Tầng network: parser IPv4 (REQ-4.1-4.4, Phụ lục A.2).

Ba con số trong header quyết định chỗ kết thúc của header và chỗ kết thúc của
dữ liệu thật — IHL, total_length, fragment_offset — và cả ba đều do bên gửi
packet điền, tức do kẻ tấn công điều khiển. Vì vậy mỗi con số đều được kiểm
tra trước khi dùng làm chỉ số (I-5), không có chỗ nào giả định header dài đúng
20 byte (REQ-4.2).
"""
import struct

from .common import ParseResult, need

IPV4_VERSION = 4
IPV4_MIN_HEADER_LEN = 20        # IHL = 5 -> 5 * 4 byte
IPV4_MIN_IHL = 5                # header không có options
IPV4_HEADER_UNIT = 4            # IHL đếm theo từ 4 byte (REQ-4.2)
FRAGMENT_OFFSET_UNIT = 8        # fragment offset đếm theo khối 8 byte

# Số protocol của tầng trên (RFC 790). Bài 1 chỉ parse TCP và UDP; ICMP để đây
# vì nó xuất hiện trong lab (ping) và là ca "transport_proto=UNKNOWN" của T5.4.
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# Hai khoá này KHÔNG nằm trong event["ipv4"] mà đi lên top-level của event
# (Phụ lục A.1, design §5.4) — pipeline lấy ra khỏi fields để cùng một giá trị
# không bị ghi ở hai chỗ trong một dòng JSON.
PROMOTED_FIELDS = ("src_ip", "dst_ip")

# "!BBHHHBBH4s4s" = đúng 20 byte của header IPv4 không options:
#   B   version (4 bit) | IHL (4 bit)      B   DSCP/ECN (bài 1 không dùng)
#   H   total_length                       H   identification
#   H   flags (3 bit) | fragment_offset (13 bit)
#   B   TTL                                B   protocol
#   H   header checksum (xem _parse_header) 4s  src IP     4s  dst IP
_IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")

# Ba bit cờ nằm ở ba bit CAO của từ 16 bit "flags + fragment offset".
_FLAG_DF = 0x4000               # bit 14: Don't Fragment
_FLAG_MF = 0x2000               # bit 13: More Fragments
_FRAGMENT_OFFSET_MASK = 0x1FFF  # 13 bit thấp


def _ip(raw: bytes) -> str:
    """4 byte -> "10.20.0.10" (dạng thập phân có dấu chấm, §5.4).

    Tự viết thay vì ipaddress.IPv4Address: kết quả cần là str để json.dumps
    ghi được thẳng, và 4 byte luôn hợp lệ nên không có ca lỗi nào để xử lý.
    """
    return ".".join(str(b) for b in raw)


def parse_ipv4(data: bytes) -> ParseResult:
    """Bytes sau header tầng liên kết -> ParseResult của tầng network.

    next_proto là protocol number (6 = TCP, 17 = UDP) để pipeline chọn parser
    transport, giống cách EtherType chọn parser network.

    KHÔNG kiểm header checksum, và đây là quyết định có chủ đích: card mạng
    hiện đại tính checksum bằng phần cứng (TX checksum offload), nên packet
    bắt được TRÊN CHÍNH MÁY GỬI thường mang checksum sai hoặc bằng 0. Kiểm
    checksum sẽ làm traffic bình thường của lab bị gắn malformed — trái V5.1.
    """
    if not need(data, 0, IPV4_MIN_HEADER_LEN):
        return ParseResult(
            error=f"ipv4 header needs {IPV4_MIN_HEADER_LEN} bytes, got {len(data)}"
        )

    (ver_ihl, _dscp_ecn, total_length, identification, flags_frag,
     ttl, protocol, _checksum, src, dst) = _IPV4_HEADER.unpack_from(data, 0)

    # Một byte chứa hai trường 4 bit: version ở nửa cao, IHL ở nửa thấp.
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    header_len = ihl * IPV4_HEADER_UNIT
    fragment_offset = flags_frag & _FRAGMENT_OFFSET_MASK

    fields = {
        "version": version,
        "ihl": ihl,                              # đơn vị 4 byte, KHÔNG phải byte
        "total_length": total_length,
        "identification": identification,
        "df": bool(flags_frag & _FLAG_DF),
        "mf": bool(flags_frag & _FLAG_MF),
        "fragment_offset": fragment_offset,      # đơn vị 8 byte
        "ttl": ttl,
        "protocol": protocol,
        # "packet này là MỘT MẢNH của một datagram lớn hơn": mảnh cuối có
        # MF=0 nhưng offset khác 0, mảnh đầu có MF=1 nhưng offset bằng 0.
        # Chỉ xét offset sẽ bỏ sót mảnh đầu, chỉ xét MF sẽ bỏ sót mảnh cuối.
        "is_fragment": bool(flags_frag & _FLAG_MF) or fragment_offset != 0,
        # Hai khoá cuối bị pipeline lấy ra khỏi đây (PROMOTED_FIELDS).
        "src_ip": _ip(src),
        "dst_ip": _ip(dst),
    }

    # Từ đây trở xuống: fields đã đủ để ghi vào event, nên mọi lỗi phát hiện
    # sau đều trả KÈM fields (ParseResult cho phép) — REQ-14.1: tầng dưới
    # parse được gì thì giữ nguyên, không ném đi cả header chỉ vì độ dài sai.
    if version != IPV4_VERSION:
        return ParseResult(
            fields=fields,
            error=f"ipv4 version is {version}, expected {IPV4_VERSION}",
        )

    if ihl < IPV4_MIN_IHL:
        # header_len < 20 -> các trường ở trên đã đọc lấn sang dữ liệu tầng
        # khác. Không thể tin và cũng không biết payload bắt đầu ở đâu.
        return ParseResult(
            fields=fields,
            error=f"ipv4 ihl={ihl} is below minimum {IPV4_MIN_IHL} "
                  f"(header would be {header_len} bytes)",
        )

    if not need(data, 0, header_len):
        # IHL khai có options nhưng dữ liệu không đủ dài chứa chúng (REQ-4.3).
        return ParseResult(
            fields=fields,
            error=f"ipv4 header declares {header_len} bytes (ihl={ihl}), "
                  f"got {len(data)}",
        )

    if total_length < header_len:
        # total_length tính CẢ header, nên nhỏ hơn header là tự mâu thuẫn.
        return ParseResult(
            fields=fields,
            error=f"ipv4 total_length={total_length} is smaller than "
                  f"header length {header_len}",
        )

    if total_length > len(data):
        # Packet khai dài hơn số byte thật có. Khác với truncated của tầng
        # capture (bản ghi PCAP tự khai bị cắt): ở đây chính header nói sai.
        return ParseResult(
            fields=fields,
            error=f"ipv4 total_length={total_length} exceeds available "
                  f"{len(data)} bytes",
        )

    return ParseResult(
        fields=fields,
        # Cắt theo total_length, KHÔNG lấy hết data[header_len:]: Ethernet đệm
        # frame ngắn lên tối thiểu 60 byte, nên data thường dài hơn packet thật
        # và phần đệm sẽ chui vào payload TCP/UDP nếu không cắt ở đây.
        payload=data[header_len:total_length],
        next_proto=protocol,
    )
