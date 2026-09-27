"""T5.2 — parser TCP (REQ-5.1-5.5, Phụ lục A.3, I-4)."""
import base64
import struct

import pytest

from idps.decode.tcp import (
    TCP_FLAGS,
    TCP_MIN_HEADER_LEN,
    flag_names,
    parse_tcp,
)

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = (0x01, 0x02, 0x04, 0x08,
                                          0x10, 0x20, 0x40, 0x80)


def tcp(src_port=54321, dst_port=80, seq=0x11223344, ack=0, data_offset=5,
        flags=0, window=64240, options=b"", payload=b""):
    """Dựng segment TCP bằng tay (xem lý do ở tests/test_ipv4.py)."""
    if len(options) % 4:
        raise AssertionError("options phải là bội số của 4 byte")
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset << 4,           # nửa thấp = reserved, để 0
        flags,
        window,
        0,                          # checksum: parser không kiểm
        0,                          # urgent pointer
    )
    return header + options + payload


# --- segment hợp lệ (REQ-5.1) -----------------------------------------------

def test_minimal_segment():
    r = parse_tcp(tcp(src_port=54321, dst_port=80, seq=0x11223344,
                      ack=0xAABBCCDD, flags=PSH | ACK, window=501,
                      payload=b"GET / HTTP/1.1\r\n\r\n"))
    assert r.error is None
    assert r.fields == {
        "src_port": 54321,
        "dst_port": 80,
        "seq": 0x11223344,
        "ack": 0xAABBCCDD,
        "data_offset": 5,
        "flags": ["PSH", "ACK"],
        "window": 501,
        "payload_len": 18,
        "payload_b64": base64.b64encode(b"GET / HTTP/1.1\r\n\r\n").decode(),
    }
    assert r.payload == b"GET / HTTP/1.1\r\n\r\n"
    assert r.next_proto is None          # port không quyết định app proto (ADR-5)


def test_field_keys_match_appendix_a3():
    assert tuple(parse_tcp(tcp()).fields) == (
        "src_port", "dst_port", "seq", "ack", "data_offset", "flags",
        "window", "payload_len", "payload_b64",
    )


def test_ports_and_seq_are_big_endian():
    r = parse_tcp(tcp(src_port=0x1234, dst_port=0x5678, seq=0x01020304))
    assert r.fields["src_port"] == 0x1234
    assert r.fields["dst_port"] == 0x5678
    assert r.fields["seq"] == 0x01020304


def test_header_only_segment_has_no_payload():
    r = parse_tcp(tcp())
    assert r.error is None
    assert r.payload == b"" and r.fields["payload_len"] == 0
    assert r.fields["payload_b64"] == ""


def test_sequence_number_can_use_the_full_32_bits():
    """seq là uint32; đọc thành int có dấu sẽ ra số âm."""
    r = parse_tcp(tcp(seq=0xFFFFFFFF, ack=0xFFFFFFFF))
    assert r.fields["seq"] == 0xFFFFFFFF
    assert r.fields["ack"] == 0xFFFFFFFF


# --- cờ: ba bước handshake phân biệt được bằng flags (REQ-5.2, TC-01) --------

def test_handshake_is_distinguishable_by_flags_alone():
    syn = parse_tcp(tcp(flags=SYN)).fields["flags"]
    syn_ack = parse_tcp(tcp(flags=SYN | ACK)).fields["flags"]
    ack = parse_tcp(tcp(flags=ACK)).fields["flags"]
    assert syn == ["SYN"]
    assert syn_ack == ["SYN", "ACK"]
    assert ack == ["ACK"]
    assert len({tuple(syn), tuple(syn_ack), tuple(ack)}) == 3


def test_flag_order_is_by_bit_value():
    """Thứ tự cố định -> cùng bộ cờ luôn ra cùng chuỗi JSON (NFR-2)."""
    assert flag_names(0xFF) == ["FIN", "SYN", "RST", "PSH", "ACK",
                               "URG", "ECE", "CWR"]


def test_no_flag_set_is_an_empty_list():
    """NULL scan: không cờ nào bật — [] chứ không phải None."""
    assert flag_names(0) == []
    assert parse_tcp(tcp(flags=0)).fields["flags"] == []


@pytest.mark.parametrize("bit,name", TCP_FLAGS)
def test_each_flag_alone(bit, name):
    assert parse_tcp(tcp(flags=bit)).fields["flags"] == [name]


def test_rst_ack_of_a_closed_port():
    """Phản hồi của port đóng — dấu hiệu quét cổng ở bài sau."""
    assert parse_tcp(tcp(flags=RST | ACK)).fields["flags"] == ["RST", "ACK"]


def test_fin_psh_urg_xmas_scan():
    assert parse_tcp(tcp(flags=FIN | PSH | URG)).fields["flags"] == [
        "FIN", "PSH", "URG"]


def test_reserved_bits_of_byte_12_do_not_become_flags():
    """Nửa thấp của byte data offset bật hết: không được lẫn vào danh sách cờ."""
    raw = bytearray(tcp(flags=SYN))
    raw[12] |= 0x0F
    r = parse_tcp(bytes(raw))
    assert r.fields["flags"] == ["SYN"]
    assert r.fields["data_offset"] == 5


# --- data offset: payload theo độ dài header thật (REQ-5.3) -----------------

def test_data_offset_8_skips_options():
    """data offset=8 -> header 32 byte -> 12 byte options không vào payload."""
    options = bytes.fromhex("020405b40101040201030307")     # MSS, SACK, WS
    assert len(options) == 12
    r = parse_tcp(tcp(data_offset=8, options=options, payload=b"BODY"))
    assert r.error is None
    assert r.fields["data_offset"] == 8
    assert r.payload == b"BODY"
    assert r.fields["payload_len"] == 4


@pytest.mark.parametrize("data_offset", [5, 6, 8, 10, 15])
def test_payload_offset_follows_data_offset(data_offset):
    options = b"\x00" * ((data_offset - 5) * 4)
    r = parse_tcp(tcp(data_offset=data_offset, options=options, payload=b"XYZ"))
    assert r.error is None and r.payload == b"XYZ"


def test_assuming_20_bytes_would_leak_options_into_payload():
    """Đối chứng cho REQ-5.3: lệch im lặng đúng bằng độ dài options."""
    options = bytes.fromhex("020405b4")
    r = parse_tcp(tcp(data_offset=6, options=options, payload=b"REAL"))
    assert r.payload == b"REAL"
    assert r.payload != options + b"REAL"


# --- ca lỗi (REQ-5.5, I-5) --------------------------------------------------

def test_data_offset_2_is_an_error():
    r = parse_tcp(tcp(data_offset=2))
    assert r.error is not None
    assert "data_offset=2" in r.error
    assert r.payload == b""
    # REQ-14.1: port và cờ vẫn giữ để còn soi được segment hỏng
    assert r.fields["dst_port"] == 80


@pytest.mark.parametrize("data_offset", [0, 1, 3, 4])
def test_every_data_offset_below_5_is_an_error(data_offset):
    assert parse_tcp(tcp(data_offset=data_offset)).error is not None


def test_data_offset_15_on_a_20_byte_segment_is_an_error():
    """Khai header 60 byte nhưng chỉ có 20 byte dữ liệu."""
    r = parse_tcp(tcp(data_offset=15))
    assert r.error is not None
    assert "60" in r.error and "20" in r.error
    assert r.payload == b"" and r.fields["payload_len"] == 0


def test_data_offset_just_one_word_too_long_is_an_error():
    """Ca biên: data offset=6 trên segment đúng 20 byte."""
    assert parse_tcp(tcp(data_offset=6)).error is not None


def test_data_offset_exactly_matching_the_segment_is_ok():
    """Ca biên đối xứng: header 24 byte trên segment 24 byte -> payload rỗng."""
    r = parse_tcp(tcp(data_offset=6, options=b"\x00" * 4))
    assert r.error is None and r.payload == b""


def test_19_bytes_is_an_error():
    r = parse_tcp(tcp()[:19])
    assert r.error is not None and "19" in r.error
    assert r.fields == {} and r.payload == b""


@pytest.mark.parametrize("size", range(0, TCP_MIN_HEADER_LEN))
def test_every_short_length_gives_error_not_exception(size):
    assert parse_tcp(b"\x00" * size).error is not None


# --- I-4: base64 giải mã ngược ra đúng bytes gốc ----------------------------

@pytest.mark.parametrize("payload", [
    b"",
    b"GET / HTTP/1.1\r\n\r\n",
    bytes(range(256)),                      # mọi giá trị byte, kể cả \x00, \xff
    b"\x00\x01\x02",
    "tiếng Việt".encode("utf-8"),
])
def test_base64_roundtrip(payload):
    r = parse_tcp(tcp(payload=payload))
    assert base64.b64decode(r.fields["payload_b64"]) == payload
    assert r.fields["payload_len"] == len(payload)


def test_payload_b64_is_ascii_only():
    """Điều kiện để json.dumps(ensure_ascii=True) không làm phình dòng."""
    b64_text = parse_tcp(tcp(payload=bytes(range(256)))).fields["payload_b64"]
    assert b64_text.isascii() and "\n" not in b64_text
