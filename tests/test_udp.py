"""T5.3 — parser UDP (REQ-6.1, 6.2, Phụ lục A.4, I-4)."""
import base64
import struct

import pytest

from idps.decode.udp import UDP_HEADER_LEN, parse_udp

DNS_QUERY = bytes.fromhex(
    "1234" "0100" "0001" "0000" "0000" "0000"      # header: 1 question
    "06" "7669" "6374696d" "03" "6c6162" "00"      # victim.lab
    "0001" "0001"                                  # QTYPE A, QCLASS IN
)


def udp(src_port=41234, dst_port=53, length=None, payload=b""):
    """Dựng datagram UDP bằng tay. length=None -> khai đúng độ dài thật."""
    if length is None:
        length = UDP_HEADER_LEN + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


# --- datagram hợp lệ (REQ-6.1) ----------------------------------------------

def test_valid_datagram():
    r = parse_udp(udp(src_port=41234, dst_port=53, payload=DNS_QUERY))
    assert r.error is None
    assert r.fields == {
        "src_port": 41234,
        "dst_port": 53,
        "length": UDP_HEADER_LEN + len(DNS_QUERY),
        "payload_len": len(DNS_QUERY),
        "payload_b64": base64.b64encode(DNS_QUERY).decode(),
    }
    assert r.payload == DNS_QUERY
    assert r.next_proto is None          # detector mới chọn app proto (ADR-5)


def test_field_keys_match_appendix_a4():
    assert tuple(parse_udp(udp()).fields) == (
        "src_port", "dst_port", "length", "payload_len", "payload_b64",
    )


def test_ports_are_big_endian():
    r = parse_udp(udp(src_port=0x1234, dst_port=0x0035))
    assert r.fields["src_port"] == 0x1234
    assert r.fields["dst_port"] == 53


def test_header_only_datagram():
    """length=8, không payload: hợp lệ (vd probe rỗng của UDP scan)."""
    r = parse_udp(udp())
    assert r.error is None
    assert r.fields["length"] == 8
    assert r.payload == b"" and r.fields["payload_len"] == 0
    assert r.fields["payload_b64"] == ""


def test_length_counts_the_header():
    """Điểm dễ nhầm: length = 8 + payload, không phải độ dài payload."""
    r = parse_udp(udp(payload=b"12345"))
    assert r.fields["length"] == 13
    assert r.fields["payload_len"] == 5


def test_max_port_number():
    r = parse_udp(udp(src_port=65535, dst_port=65535))
    assert r.fields["src_port"] == 65535 and r.fields["dst_port"] == 65535


# --- dữ liệu không đủ (REQ-6.2, I-5) ----------------------------------------

def test_7_bytes_is_an_error():
    r = parse_udp(udp()[:7])
    assert r.error is not None
    assert "7" in r.error and "8" in r.error
    assert r.fields == {} and r.payload == b""


@pytest.mark.parametrize("size", range(0, UDP_HEADER_LEN))
def test_every_short_length_gives_error_not_exception(size):
    assert parse_udp(b"\x00" * size).error is not None


# --- trường length không khớp dữ liệu thật (REQ-6.2) ------------------------

def test_length_6_is_an_error():
    """length tính cả header nên không thể nhỏ hơn 8."""
    r = parse_udp(udp(length=6))
    assert r.error is not None
    assert "length=6" in r.error
    assert r.payload == b""
    # REQ-14.1: port vẫn giữ lại
    assert r.fields["dst_port"] == 53


@pytest.mark.parametrize("length", [0, 1, 7])
def test_every_length_below_8_is_an_error(length):
    assert parse_udp(udp(length=length)).error is not None


def test_length_longer_than_data_is_an_error():
    """Khai 100 byte nhưng chỉ có 13 byte thật."""
    r = parse_udp(udp(length=100, payload=b"12345"))
    assert r.error is not None
    assert "100" in r.error and "13" in r.error
    assert r.payload == b""


def test_length_shorter_than_data_is_an_error():
    """Khai 9 byte nhưng có 13 byte: 4 byte không ai nhận -> hỏng."""
    r = parse_udp(udp(length=9, payload=b"12345"))
    assert r.error is not None and "9" in r.error


def test_length_off_by_one_is_an_error():
    r = parse_udp(udp(length=12, payload=b"12345"))
    assert r.error is not None


def test_exact_length_is_the_only_accepted_value():
    """Ca biên: chỉ đúng một giá trị length được nhận cho cùng một datagram."""
    ok = 0
    for length in range(0, 40):
        if parse_udp(udp(length=length, payload=b"1234")).error is None:
            ok += 1
            assert length == UDP_HEADER_LEN + 4
    assert ok == 1


# --- I-4: base64 giải mã ngược ra đúng bytes gốc ----------------------------

@pytest.mark.parametrize("payload", [
    b"",
    DNS_QUERY,
    bytes(range(256)),
    b"\x00" * 10,
    "tiếng Việt".encode("utf-8"),
])
def test_base64_roundtrip(payload):
    r = parse_udp(udp(payload=payload))
    assert base64.b64decode(r.fields["payload_b64"]) == payload
    assert r.fields["payload_len"] == len(payload)


def test_payload_b64_is_ascii_only():
    b64_text = parse_udp(udp(payload=bytes(range(256)))).fields["payload_b64"]
    assert b64_text.isascii() and "\n" not in b64_text
