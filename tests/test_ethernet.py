"""T2.4 — parser tầng liên kết Ethernet II (REQ-17.1-17.3)."""
import pytest

from idps.decode.ethernet import (
    ETHERNET_HEADER_LEN,
    LINKTYPE_ETHERNET,
    link_name,
    parse_ethernet,
    parse_link,
)

DST = bytes.fromhex("02420a14000a")       # 02:42:0a:14:00:0a (victim)
SRC = bytes.fromhex("02420a0a000a")       # 02:42:0a:0a:00:0a (attacker)
LINKTYPE_LINUX_SLL = 113                  # Linux cooked — bài 1 chưa hỗ trợ


def frame(ethertype=0x0800, payload=b"", dst=DST, src=SRC):
    return dst + src + ethertype.to_bytes(2, "big") + payload


# --- frame hợp lệ -----------------------------------------------------------

def test_ipv4_frame():
    r = parse_ethernet(frame(0x0800, b"\x45\x00payload"))
    assert r.error is None
    assert r.fields == {
        "src_mac": "02:42:0a:0a:00:0a",
        "dst_mac": "02:42:0a:14:00:0a",
        "ethertype": 0x0800,
    }
    assert r.next_proto == 0x0800
    assert r.payload == b"\x45\x00payload"


def test_dst_comes_first_on_the_wire():
    """Đổi chỗ hai MAC trong frame phải đổi chỗ hai trường trong kết quả."""
    r = parse_ethernet(frame(dst=SRC, src=DST))
    assert r.fields["dst_mac"] == "02:42:0a:0a:00:0a"
    assert r.fields["src_mac"] == "02:42:0a:14:00:0a"


def test_arp_frame_is_not_an_error():
    """EtherType lạ vẫn parse xong tầng link; pipeline mới là nơi gán UNKNOWN."""
    r = parse_ethernet(frame(0x0806, b"arp body"))
    assert r.error is None
    assert r.fields["ethertype"] == 0x0806
    assert r.next_proto == 0x0806


def test_ethertype_is_big_endian():
    """Đọc sai thứ tự byte sẽ ra 0x0008 thay vì 0x0800."""
    assert parse_ethernet(frame(0x86DD)).fields["ethertype"] == 0x86DD


def test_header_only_frame():
    """Đúng 14 byte: không lỗi, payload rỗng (ca biên của need())."""
    r = parse_ethernet(frame())
    assert r.error is None and r.payload == b""


def test_mac_is_lowercase_hex_with_leading_zero():
    r = parse_ethernet(frame(dst=bytes.fromhex("0002ffAB0c0d"), src=SRC))
    assert r.fields["dst_mac"] == "00:02:ff:ab:0c:0d"


# --- frame hỏng (I-5) -------------------------------------------------------

def test_short_frame():
    r = parse_ethernet(b"\x00" * 13)
    assert r.error is not None and "13" in r.error
    assert r.fields == {} and r.payload == b"" and r.next_proto is None


def test_empty_frame():
    assert parse_ethernet(b"").error is not None


@pytest.mark.parametrize("size", range(0, ETHERNET_HEADER_LEN))
def test_every_short_length_gives_error_not_exception(size):
    assert parse_ethernet(b"\x00" * size).error is not None


# --- chọn parser theo linktype (REQ-17.2, NFR-8) ----------------------------

def test_parse_link_ethernet():
    r = parse_link(LINKTYPE_ETHERNET, frame(0x0800))
    assert r is not None and r.error is None


def test_parse_link_unsupported_linktype():
    """113 chưa hỗ trợ -> None, KHÔNG phải ParseResult(error=...)."""
    assert parse_link(LINKTYPE_LINUX_SLL, frame(0x0800)) is None


def test_parse_link_does_not_look_at_data_for_unknown_linktype():
    assert parse_link(LINKTYPE_LINUX_SLL, b"") is None


def test_link_name():
    assert link_name(LINKTYPE_ETHERNET) == "Ethernet"
    assert link_name(LINKTYPE_LINUX_SLL) is None
