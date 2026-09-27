"""Tầng liên kết: chọn parser theo linktype, parse Ethernet II (REQ-17.1-17.3).

Tách tầng liên kết thành một bước riêng, chọn bằng bảng tra, là cách thoả
NFR-8: thêm Linux cooked (113) hay raw IP (101) ở bài sau chỉ là thêm một hàm
parse_* và một dòng trong LINK_PARSERS — không đụng tới ipv4/tcp/udp.
"""
import struct

from .common import ParseResult, need

LINKTYPE_ETHERNET = 1          # DLT_EN10MB (Phụ lục D)
ETHERNET_HEADER_LEN = 14       # 6 dst + 6 src + 2 ethertype
ETHERTYPE_IPV4 = 0x0800

# "!6s6sH": ! = big-endian (network byte order). Mọi số nhiều byte trong header
# giao thức mạng đều big-endian; máy x86 là little-endian nên bỏ ! sẽ đọc
# 0x0800 thành 0x0008.
_ETHERNET_HEADER = struct.Struct("!6s6sH")


def _mac(raw: bytes) -> str:
    """6 byte -> "aa:bb:cc:dd:ee:ff" (chữ thường, đúng định dạng §5.4)."""
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(data: bytes) -> ParseResult:
    """Header Ethernet II. Trên dây thứ tự là DST trước rồi mới SRC.

    (Lý do: switch chỉ cần đọc 6 byte đầu đã biết chuyển frame đi đâu, không
    phải đọc hết header.) Event ghi src_mac trước cho dễ đọc — §5.4.
    """
    if not need(data, 0, ETHERNET_HEADER_LEN):
        return ParseResult(
            error=f"ethernet header needs {ETHERNET_HEADER_LEN} bytes, got {len(data)}"
        )
    dst_mac, src_mac, ethertype = _ETHERNET_HEADER.unpack_from(data, 0)
    return ParseResult(
        fields={
            "src_mac": _mac(src_mac),
            "dst_mac": _mac(dst_mac),
            "ethertype": ethertype,
        },
        # Phần còn lại của frame. Ethernet đệm frame ngắn lên tối thiểu 60 byte,
        # nên payload ở đây có thể DÀI HƠN dữ liệu thật — tầng IPv4 cắt lại
        # theo total_length (T5.1), tầng này không có cách nào biết.
        payload=data[ETHERNET_HEADER_LEN:],
        # EtherType là gợi ý chọn parser tầng network cho pipeline.
        next_proto=ethertype,
    )


# Bảng tra linktype -> (tên ghi vào event, hàm parse). Phụ lục D: bài 1 chỉ có
# Ethernet II.
LINK_PARSERS = {
    LINKTYPE_ETHERNET: ("Ethernet", parse_ethernet),
}


def link_name(linktype: int) -> str | None:
    """Tên tầng liên kết để ghi vào event; None nếu linktype chưa hỗ trợ."""
    entry = LINK_PARSERS.get(linktype)
    return entry[0] if entry is not None else None


def parse_link(linktype: int, data: bytes) -> ParseResult | None:
    """None = linktype chưa hỗ trợ; ParseResult = đã thử parse (có thể có error).

    Phân biệt None với ParseResult(error=...) là có chủ đích (REQ-17.2 so với
    REQ-15.2): "chương trình chưa biết linktype này" khác hẳn "byte trong
    frame không khớp header". Cái đầu cho status unknown, cái sau malformed.
    """
    entry = LINK_PARSERS.get(linktype)
    if entry is None:
        return None
    _name, parser = entry
    return parser(data)
