"""T5.1 — parser IPv4 (REQ-4.1-4.4, Phụ lục A.2, I-5)."""
import struct

import pytest

from idps.decode.ipv4 import (
    IPV4_MIN_HEADER_LEN,
    PROMOTED_FIELDS,
    PROTO_TCP,
    PROTO_UDP,
    parse_ipv4,
)

SRC = "10.10.0.10"          # attacker
DST = "10.20.0.10"          # victim

DF = 0x4000
MF = 0x2000


def raw_ip(s: str) -> bytes:
    return bytes(int(part) for part in s.split("."))


def ip(ihl=5, total_length=None, ident=0x1234, flags=0, frag_offset=0,
       ttl=64, proto=PROTO_TCP, src=SRC, dst=DST, options=b"", payload=b"",
       version=4, pad=b""):
    """Dựng packet IPv4 bằng tay.

    Tự dựng từng byte thay vì nhờ Scapy là có chủ đích: test phải kiểm được
    những packet mà Scapy sẽ từ chối tạo (IHL=3, total_length khai sai), và
    dùng Scapy để kiểm parser tự viết thì hai bên có thể sai giống nhau.

    pad = phần đệm Ethernet nối SAU packet, không tính vào total_length.
    """
    if len(options) % 4:
        raise AssertionError("options phải là bội số của 4 byte")
    if ihl == 5 and options:
        raise AssertionError("có options thì IHL phải > 5")
    header_len = ihl * 4
    if total_length is None:
        total_length = header_len + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) | ihl,
        0,                                  # DSCP/ECN
        total_length,
        ident,
        flags | frag_offset,
        ttl,
        proto,
        0,                                  # checksum: parser cố tình không kiểm
        raw_ip(src),
        raw_ip(dst),
    )
    return header + options + payload + pad


# --- packet hợp lệ (REQ-4.1) -------------------------------------------------

def test_minimal_header():
    """Header 20 byte, không options: mọi trường của A.2 có mặt và đúng."""
    r = parse_ipv4(ip(ttl=64, ident=0x1234, flags=DF, proto=PROTO_TCP,
                      payload=b"tcp segment"))
    assert r.error is None
    assert r.fields == {
        "version": 4,
        "ihl": 5,
        "total_length": IPV4_MIN_HEADER_LEN + len(b"tcp segment"),
        "identification": 0x1234,
        "df": True,
        "mf": False,
        "fragment_offset": 0,
        "ttl": 64,
        "protocol": PROTO_TCP,
        "is_fragment": False,
        "src_ip": SRC,
        "dst_ip": DST,
    }
    assert r.payload == b"tcp segment"
    assert r.next_proto == PROTO_TCP


def test_field_keys_match_appendix_a2():
    """Đúng tập khoá, đúng thứ tự design §5.4 (+ hai khoá đi lên top-level)."""
    r = parse_ipv4(ip())
    assert tuple(r.fields) == (
        "version", "ihl", "total_length", "identification", "df", "mf",
        "fragment_offset", "ttl", "protocol", "is_fragment", "src_ip", "dst_ip",
    )
    assert PROMOTED_FIELDS == ("src_ip", "dst_ip")


def test_next_proto_selects_transport_parser():
    assert parse_ipv4(ip(proto=PROTO_UDP)).next_proto == PROTO_UDP
    assert parse_ipv4(ip(proto=1)).next_proto == 1        # ICMP


def test_addresses_are_dotted_decimal():
    r = parse_ipv4(ip(src="0.0.0.0", dst="255.255.255.255"))
    assert r.fields["src_ip"] == "0.0.0.0"
    assert r.fields["dst_ip"] == "255.255.255.255"


def test_multibyte_fields_are_big_endian():
    """Đọc sai thứ tự byte sẽ ra 0x3412 thay vì 0x1234."""
    assert parse_ipv4(ip(ident=0x1234)).fields["identification"] == 0x1234


def test_header_only_packet():
    """total_length = 20, không payload: hợp lệ, payload rỗng."""
    r = parse_ipv4(ip())
    assert r.error is None and r.payload == b""


# --- IHL: vị trí payload theo độ dài header thật (REQ-4.2) -------------------

def test_ihl_6_moves_payload_to_byte_24():
    """IHL=6 -> header 24 byte -> payload bắt đầu SAU 4 byte options."""
    options = bytes.fromhex("94040000")      # Router Alert, 4 byte
    r = parse_ipv4(ip(ihl=6, options=options, payload=b"PAYLOAD"))
    assert r.error is None
    assert r.fields["ihl"] == 6
    assert r.fields["total_length"] == 24 + len(b"PAYLOAD")
    assert r.payload == b"PAYLOAD"           # không phải options + PAYLOAD


@pytest.mark.parametrize("ihl", [5, 6, 7, 10, 15])
def test_payload_offset_follows_ihl_for_every_valid_ihl(ihl):
    options = b"\x00" * ((ihl - 5) * 4)
    r = parse_ipv4(ip(ihl=ihl, options=options, payload=b"XYZ"))
    assert r.error is None and r.payload == b"XYZ"


def test_assuming_20_bytes_would_be_wrong():
    """Đối chứng cho REQ-4.2: nếu parser cứng 20 byte thì payload sẽ lệch."""
    options = b"\x01\x01\x01\x00"
    r = parse_ipv4(ip(ihl=6, options=options, payload=b"REAL"))
    assert r.payload == b"REAL"
    assert r.payload != options + b"REAL"


# --- fragment (REQ-4.4) -----------------------------------------------------

def test_fragment_offset_not_zero_is_a_fragment():
    """Mảnh thứ hai: offset khác 0 -> is_fragment=True (pipeline sẽ bỏ transport)."""
    r = parse_ipv4(ip(flags=MF, frag_offset=185))
    assert r.error is None
    assert r.fields["fragment_offset"] == 185
    assert r.fields["mf"] is True
    assert r.fields["is_fragment"] is True


def test_first_fragment_is_also_a_fragment():
    """MF=1, offset=0: mảnh ĐẦU — vẫn là mảnh, nhưng có header transport."""
    r = parse_ipv4(ip(flags=MF, frag_offset=0))
    assert r.fields["is_fragment"] is True
    assert r.fields["fragment_offset"] == 0


def test_last_fragment_has_mf_zero():
    """Mảnh CUỐI: MF=0 nhưng offset khác 0 — chỉ xét MF sẽ bỏ sót ca này."""
    r = parse_ipv4(ip(flags=0, frag_offset=370))
    assert r.fields["mf"] is False
    assert r.fields["is_fragment"] is True


def test_plain_packet_is_not_a_fragment():
    r = parse_ipv4(ip(flags=DF))
    assert r.fields["is_fragment"] is False
    assert r.fields["df"] is True and r.fields["mf"] is False


def test_flags_and_offset_share_one_16_bit_word():
    """DF|MF|offset nằm chung một từ: tách sai mask sẽ làm offset sai."""
    r = parse_ipv4(ip(flags=DF | MF, frag_offset=0x1FFF))
    assert r.fields["df"] is True
    assert r.fields["mf"] is True
    assert r.fields["fragment_offset"] == 0x1FFF


def test_reserved_bit_does_not_leak_into_offset():
    """Bit 15 (evil bit) bật: offset vẫn phải bằng 0."""
    r = parse_ipv4(ip(flags=0x8000, frag_offset=0))
    assert r.fields["fragment_offset"] == 0


# --- dữ liệu không đủ (REQ-4.3, I-5) ----------------------------------------

def test_19_bytes_is_an_error():
    r = parse_ipv4(ip()[:19])
    assert r.error is not None
    assert "19" in r.error and "20" in r.error
    assert r.fields == {} and r.payload == b"" and r.next_proto is None


@pytest.mark.parametrize("size", range(0, IPV4_MIN_HEADER_LEN))
def test_every_short_length_gives_error_not_exception(size):
    assert parse_ipv4(b"\x00" * size).error is not None


def test_ihl_3_is_an_error():
    """IHL=3 -> header 12 byte < 20: các trường đã đọc lấn sang tầng khác."""
    r = parse_ipv4(ip(ihl=3, total_length=20))
    assert r.error is not None
    assert "ihl=3" in r.error
    assert r.payload == b"" and r.next_proto is None
    # REQ-14.1: vẫn giữ những gì đã đọc được để người phân tích còn xem được
    assert r.fields["src_ip"] == SRC


@pytest.mark.parametrize("ihl", [0, 1, 4])
def test_every_ihl_below_5_is_an_error(ihl):
    assert parse_ipv4(ip(ihl=ihl, total_length=20)).error is not None


def test_ihl_declares_options_that_are_not_there():
    """IHL=6 (24 byte) nhưng chỉ có 20 byte dữ liệu."""
    r = parse_ipv4(struct.pack("!BBHHHBBH4s4s", (4 << 4) | 6, 0, 24, 0, 0,
                               64, PROTO_TCP, 0, raw_ip(SRC), raw_ip(DST)))
    assert r.error is not None and "24" in r.error
    assert r.next_proto is None


def test_total_length_longer_than_data_is_an_error():
    """Header khai 100 byte nhưng chỉ có 25 byte thật."""
    r = parse_ipv4(ip(total_length=100, payload=b"12345"))
    assert r.error is not None
    assert "100" in r.error and "25" in r.error
    assert r.next_proto is None          # không đi lên transport


def test_total_length_smaller_than_header_is_an_error():
    r = parse_ipv4(ip(ihl=6, options=b"\x00" * 4, total_length=22))
    assert r.error is not None and "22" in r.error


def test_version_6_in_an_ipv4_slot_is_an_error():
    """EtherType đã nói 0x0800 nhưng version lại là 6 -> dữ liệu tự mâu thuẫn."""
    r = parse_ipv4(ip(version=6))
    assert r.error is not None and "version" in r.error
    assert r.fields["version"] == 6


# --- padding của Ethernet (lý do phải cắt theo total_length) -----------------

def test_ethernet_padding_is_cut_by_total_length():
    """Frame ngắn bị đệm lên 60 byte: phần đệm KHÔNG được vào payload."""
    r = parse_ipv4(ip(payload=b"AB", pad=b"\x00" * 24))
    assert r.error is None                   # đệm không phải lỗi
    assert r.payload == b"AB"
    assert len(r.payload) == r.fields["total_length"] - IPV4_MIN_HEADER_LEN


def test_padding_with_junk_bytes_is_still_cut():
    """Một số NIC đệm bằng rác chứ không bằng 0 — vẫn phải cắt đúng."""
    r = parse_ipv4(ip(payload=b"AB", pad=b"\xde\xad\xbe\xef" * 6))
    assert r.error is None and r.payload == b"AB"


def test_padding_does_not_change_next_proto():
    assert parse_ipv4(ip(proto=PROTO_UDP, pad=b"\x00" * 20)).next_proto == PROTO_UDP
