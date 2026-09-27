"""T6.2 — detector + registry (REQ-10.1-10.4, REQ-11.1, 15.4, NFR-6, ADR-5)."""
import dataclasses
import random

import pytest

from idps.decode.detector import (APP_PROTOCOLS, HTTP_METHODS, AppProto,
                                  Detection, app_proto_by_name, detect,
                                  matches_http)

GET = b"GET / HTTP/1.1\r\nHost: 10.20.0.10\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhi"
CLIENT_PORT = 40470          # port ephemeral như trong lab_mixed.pcap


def http(sport=CLIENT_PORT, dport=80, payload=GET, transport="TCP"):
    """Gọi detect() cho một segment TCP đi từ client tới server."""
    return detect(transport, sport, dport, payload)


# --- port chuẩn: cả port lẫn payload đều khớp (REQ-10.1, 10.4) ---------------

def test_get_on_port_80():
    assert http() == Detection("HTTP", "port+payload")


def test_response_direction_also_matches_the_port():
    """sport=80: response đi từ server về. Phải xét CẢ HAI port, không chỉ dst."""
    assert http(sport=80, dport=CLIENT_PORT, payload=RESPONSE) == Detection(
        "HTTP", "port+payload")


@pytest.mark.parametrize("method", HTTP_METHODS)
def test_every_method_of_req_10_3(method):
    payload = f"{method} /index.html HTTP/1.1\r\n\r\n".encode()
    assert http(payload=payload).app_proto == "HTTP"


@pytest.mark.parametrize("version", [b"HTTP/1.0", b"HTTP/1.1"])
def test_both_http_1_x_versions(version):
    assert http(payload=version + b" 404 Not Found\r\n\r\n").app_proto == "HTTP"


# --- REQ-11.1 / TC-13: port không chuẩn (điểm thưởng) -----------------------

def test_nonstandard_port():
    """Điểm mấu chốt của REQ-11.1: 8081 không có trong registry, payload cứu."""
    assert http(dport=8081) == Detection("HTTP", "payload")


@pytest.mark.parametrize("port", [8081, 4444, 1337, 65535, 1])
def test_http_is_found_on_any_port(port):
    assert http(dport=port) == Detection("HTTP", "payload")


def test_nonstandard_port_response_too():
    assert http(sport=8081, dport=CLIENT_PORT, payload=RESPONSE).method == "payload"


# --- REQ-10.2: port khớp nhưng payload không khớp -> KHÔNG gán --------------

def test_binary_payload_on_port_80_is_unknown():
    """Shell ngược núp ở port 80 vẫn không phải HTTP."""
    assert http(payload=bytes.fromhex("0102ff00deadbeef")) == Detection(
        "UNKNOWN", None)


def test_ssh_banner_on_port_80_is_unknown():
    assert http(payload=b"SSH-2.0-OpenSSH_9.6\r\n").app_proto == "UNKNOWN"


def test_tls_client_hello_on_port_80_is_unknown():
    """Byte đầu 0x16 = handshake record của TLS."""
    assert http(payload=b"\x16\x03\x01\x02\x00\x01").app_proto == "UNKNOWN"


# --- REQ-15.4: payload rỗng không phải lỗi, cũng không phải UNKNOWN ---------

def test_empty_payload_has_no_protocol():
    assert http(payload=b"") == Detection(None, None)


def test_empty_payload_on_nonstandard_port_too():
    assert http(dport=8081, payload=b"") == Detection(None, None)


# --- chữ ký phải khớp CHÍNH XÁC ---------------------------------------------

def test_getx_is_not_http():
    """Thiếu dấu cách sau method -> không phải request line (RFC 9112 §3)."""
    assert matches_http(b"GETX / HTTP/1.1\r\n") is False
    assert http(payload=b"GETX / HTTP/1.1\r\n").app_proto == "UNKNOWN"


def test_method_without_the_trailing_space_is_not_http():
    assert matches_http(b"GET") is False
    assert matches_http(b"GET ") is True          # 4 byte đã đủ chữ ký


def test_method_is_case_sensitive():
    """RFC 9110 §9.1: method phân biệt hoa thường, "get" không hợp lệ."""
    assert matches_http(b"get / HTTP/1.1\r\n") is False


def test_http_2_preface_is_not_http_1_x():
    """Chữ ký kết nối HTTP/2; thân là frame nhị phân, parser 1.x đọc ra rác."""
    assert matches_http(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") is False


def test_version_prefix_must_be_1_x():
    assert matches_http(b"HTTP/2 200 OK\r\n") is False
    assert matches_http(b"HTTP/") is False


@pytest.mark.parametrize("payload", [b"", b"G", b"GE", b"H", b"HTTP", b"\x00"])
def test_short_payload_never_raises(payload):
    assert matches_http(payload) in (True, False)


# --- transport phải khớp (Phụ lục C) ----------------------------------------

def test_http_signature_on_udp_is_unknown():
    """HTTP chỉ đăng ký ở TCP: cùng bytes đó trên UDP không được gán HTTP."""
    assert http(dport=80, transport="UDP").app_proto == "UNKNOWN"


def test_unsupported_transport_name_is_unknown():
    assert detect("SCTP", 1, 80, GET).app_proto == "UNKNOWN"


# --- I-1/NFR-2: không ném và tất định ---------------------------------------

def test_random_payloads_never_raise():
    rng = random.Random(20260927)
    for _ in range(500):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 60)))
        result = detect("TCP", rng.randrange(65536), rng.randrange(65536), payload)
        assert result.app_proto in {None, "UNKNOWN", *(p.name for p in APP_PROTOCOLS)}
        assert result.method in {None, "port+payload", "payload"}


def test_same_input_gives_same_result():
    assert [http() for _ in range(5)] == [Detection("HTTP", "port+payload")] * 5


def test_detection_is_immutable():
    """Frozen: một tầng dưới không thể sửa kết quả nhận diện của tầng trên."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        http().app_proto = "DNS"


# --- registry (NFR-6) -------------------------------------------------------

def test_registry_lookup_by_name():
    proto = app_proto_by_name("HTTP")
    assert proto is not None and proto.transport == "TCP" and 80 in proto.ports


def test_registry_lookup_of_unknown_name():
    """"UNKNOWN" và None không phải tên giao thức -> không có dòng registry."""
    assert app_proto_by_name("UNKNOWN") is None
    assert app_proto_by_name("SMTP") is None      # Phase 9 mới thêm


def test_registry_entries_are_well_formed():
    for proto in APP_PROTOCOLS:
        assert isinstance(proto, AppProto)
        assert proto.transport in {"TCP", "UDP"}
        assert proto.name == proto.name.upper()
        assert proto.ports and all(0 < port < 65536 for port in proto.ports)
        assert callable(proto.matches)


def test_registry_names_are_unique():
    names = [proto.name for proto in APP_PROTOCOLS]
    assert len(names) == len(set(names))          # app_proto_by_name mới xác định


def test_protocol_entry_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        APP_PROTOCOLS[0].ports = (8081,)
