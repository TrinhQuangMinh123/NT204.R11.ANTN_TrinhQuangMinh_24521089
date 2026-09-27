"""T6.2 — detector + registry (REQ-10.1-10.4, REQ-11.1, 15.4, NFR-6, ADR-5)."""
import dataclasses
import random

import pytest

from idps.decode.detector import (APP_PROTOCOLS, HTTP_METHODS, AppProto,
                                  Detection, app_proto_by_name, detect,
                                  matches_dns, matches_http, matches_smtp)
from idps.decode.dns import parse_dns
from idps.decode.http import parse_http
from idps.decode.smtp import parse_smtp

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
    """"UNKNOWN" không phải tên giao thức -> không có dòng registry.

    "FTP" đứng đây thay cho "SMTP" của bản trước: từ T9.2 SMTP đã là một dòng
    thật, nên ca "tên chưa có trong registry" cần một giao thức ngoài phạm vi
    bài (REQ, §3 phạm vi: chỉ HTTP/DNS/SMTP).
    """
    assert app_proto_by_name("UNKNOWN") is None
    assert app_proto_by_name("FTP") is None


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


# --- T6.3: dòng registry trỏ tới parser thật ---------------------------------

def test_http_registry_entry_points_at_the_http_parser():
    """NFR-6: pipeline lấy parser QUA registry, không giữ bảng riêng."""
    proto = app_proto_by_name("HTTP")
    assert proto.parse is parse_http
    assert proto.parse(GET).fields["method"] == "GET"


# --- T8.2: DNS (REQ-10.2, 11.2, Phụ lục C, NFR-6) ---------------------------

# Query "victim.lab" A, đúng message mà `dig` gửi trong lab (xem TEST/TC-07).
DNS_QUERY = bytes.fromhex(
    "1234" "0100" "0001" "0000" "0000" "0000"      # header: 1 question
    "06" "7669" "6374696d" "03" "6c6162" "00"      # victim.lab
    "0001" "0001"                                  # QTYPE A, QCLASS IN
)
# Response cho chính query đó, answer dùng tên nén 0xC00C.
DNS_RESPONSE = DNS_QUERY[:2] + bytes.fromhex(
    "8180" "0001" "0001" "0000" "0000"
    "06" "7669" "6374696d" "03" "6c6162" "00" "0001" "0001"
    "c00c" "0001" "0001" "0000012c" "0004" "0a14000a"      # A 10.20.0.10, TTL 300
)
DNS_PORT = 53
MDNS_PORT = 5353             # port lạ nhưng payload vẫn là DNS (REQ-11.2)


def dns(sport=40470, dport=DNS_PORT, payload=DNS_QUERY, transport="UDP"):
    return detect(transport, sport, dport, payload)


def test_dns_query_on_port_53():
    assert dns() == Detection("DNS", "port+payload")


def test_dns_response_direction():
    """sport=53: response từ server về — cùng lý do như HTTP, xét cả hai port."""
    assert dns(sport=DNS_PORT, dport=40470, payload=DNS_RESPONSE) == Detection(
        "DNS", "port+payload")


def test_dns_on_nonstandard_port():
    """REQ-11.2: payload DNS hợp lệ trên port 5353 -> nhận nhờ payload."""
    assert dns(dport=MDNS_PORT) == Detection("DNS", "payload")
    assert dns(sport=MDNS_PORT, dport=MDNS_PORT) == Detection("DNS", "payload")


def test_eleven_bytes_on_port_53_is_unknown():
    """Ngắn hơn header DNS (12 byte) -> UNKNOWN, dù port khớp (REQ-10.2)."""
    assert dns(payload=b"\x00" * 11) == Detection("UNKNOWN", None)


def test_qdcount_zero_on_port_53_is_unknown():
    """Đủ 12 byte nhưng QDCOUNT=0: không có question nào để kiểm -> không gán."""
    payload = bytes.fromhex("1234" "0100" "0000" "0000" "0000" "0000")
    assert dns(payload=payload) == Detection("UNKNOWN", None)


def test_truncated_question_on_port_53_is_unknown():
    """Header hợp lệ nhưng question bị cắt -> cấu trúc không tự nhất quán."""
    assert dns(payload=DNS_QUERY[:-3]) == Detection("UNKNOWN", None)


def test_dns_signature_is_not_applied_to_tcp():
    """Cùng bytes đó trên TCP: DNS trong bài chỉ chạy trên UDP (A3)."""
    assert dns(transport="TCP", payload=DNS_QUERY) == Detection("UNKNOWN", None)


def test_http_payload_on_udp_53_is_unknown():
    """Chữ ký HTTP không được dùng cho UDP, và GET không phải DNS hợp lệ."""
    assert dns(payload=GET) == Detection("UNKNOWN", None)


def test_matches_dns_directly():
    assert matches_dns(DNS_QUERY) is True
    assert matches_dns(DNS_RESPONSE) is True
    assert matches_dns(b"") is False
    assert matches_dns(GET) is False


def test_dns_registry_entry_points_at_the_dns_parser():
    """NFR-6: pipeline lấy parser QUA registry — không có bảng thứ hai."""
    proto = app_proto_by_name("DNS")
    assert proto.parse is parse_dns
    assert proto.transport == "UDP" and proto.ports == (DNS_PORT,)
    assert proto.parse(DNS_QUERY).fields["questions"] == [
        {"name": "victim.lab", "type": "A"},
    ]


def test_adding_dns_did_not_change_http_detection():
    """Hồi quy của NFR-6: registry dài ra nhưng kết quả của HTTP không đổi."""
    assert http() == Detection("HTTP", "port+payload")
    assert http(dport=8081) == Detection("HTTP", "payload")
    assert http(payload=b"\x16\x03\x01\x00\x95") == Detection("UNKNOWN", None)


# --- T9.2: SMTP (REQ-10.2, 11.3, Phụ lục C, NFR-6) --------------------------

EHLO = b"EHLO attacker.lab\r\n"
# Banner aiosmtpd gửi ra ngay khi TCP bắt tay xong (xem TEST/TC-10).
BANNER = b"220 victim.lab Python SMTP 1.4.6\r\n"
SMTP_PORT = 25
SUBMISSION_PORT = 2525       # port lạ nhưng payload vẫn là SMTP (REQ-11.3)


def smtp(sport=40470, dport=SMTP_PORT, payload=EHLO, transport="TCP"):
    return detect(transport, sport, dport, payload)


def test_ehlo_on_port_25():
    assert smtp() == Detection("SMTP", "port+payload")


def test_banner_direction_also_matches_the_port():
    """sport=25: reply đi từ server về — chữ ký khác chiều đi, port thì không."""
    assert smtp(sport=SMTP_PORT, dport=40470, payload=BANNER) == Detection(
        "SMTP", "port+payload")


def test_smtp_on_nonstandard_port():
    """REQ-11.3: reply trên port 2525 -> nhận nhờ payload, không nhờ port."""
    assert smtp(sport=SUBMISSION_PORT, dport=40470,
                payload=BANNER) == Detection("SMTP", "payload")
    assert smtp(dport=SUBMISSION_PORT, payload=EHLO) == Detection("SMTP",
                                                                  "payload")


def test_arbitrary_text_on_port_25_is_unknown():
    """REQ-10.2: port khớp mà payload không khớp thì KHÔNG gán."""
    assert smtp(payload=b"hello world\r\n") == Detection("UNKNOWN", None)


def test_ehlox_on_port_25_is_unknown():
    """Chữ ký đòi dấu phân cách sau tên lệnh, đúng như "GET " của HTTP."""
    assert smtp(payload=b"EHLOX attacker.lab\r\n") == Detection("UNKNOWN", None)


@pytest.mark.parametrize("payload", [b"", b"2", b"25", b"250", b"E", b"EHL"])
def test_short_payload_on_port_25_never_raises(payload):
    """"250" thiếu dấu phân cách -> chưa đủ căn cứ, không đoán (I-5)."""
    assert smtp(payload=payload).app_proto in (None, "UNKNOWN")


def test_smtp_signature_is_not_applied_to_udp():
    assert smtp(transport="UDP", payload=EHLO) == Detection("UNKNOWN", None)


def test_matches_smtp_directly():
    assert matches_smtp(EHLO) is True
    assert matches_smtp(BANNER) is True
    assert matches_smtp(b"250-victim.lab\r\n") is True
    assert matches_smtp(b"mail from:<a@b>\r\n") is True
    assert matches_smtp(b"") is False
    assert matches_smtp(GET) is False


def test_smtp_registry_entry_points_at_the_smtp_parser():
    """NFR-6: pipeline lấy parser QUA registry — không có bảng thứ hai."""
    proto = app_proto_by_name("SMTP")
    assert proto.parse is parse_smtp
    assert proto.transport == "TCP" and proto.ports == (SMTP_PORT,)
    assert proto.parse(EHLO).fields["command"] == "EHLO"


def test_http_and_smtp_signatures_do_not_overlap():
    """Hai dòng TCP nằm cạnh nhau: không payload nào khớp cả hai, nên thứ tự
    thử trong registry không đổi được kết quả của bất kỳ ca nào."""
    for payload in (GET, RESPONSE, EHLO, BANNER, b"DATA\r\n",
                    b"HTTP/1.1 404 Not Found\r\n"):
        assert not (matches_http(payload) and matches_smtp(payload))


def test_smtp_signature_does_not_steal_http_traffic_on_port_80():
    """Mấu chốt của V9.1 ở mức unit: port 80 -> HTTP được thử trước, nên một
    request/response HTTP không bao giờ thành SMTP."""
    assert http() == Detection("HTTP", "port+payload")
    assert http(sport=80, dport=40470, payload=RESPONSE) == Detection(
        "HTTP", "port+payload")


def test_a_body_fragment_starting_with_three_digits_is_the_known_risk_r5():
    """Ca ngược của rủi ro R5, ghi lại để khỏi tưởng là bug: một mảnh body HTTP
    mở đầu bằng "404 " KHÔNG còn chữ ký HTTP nào (đây là giữa luồng), nên chữ ký
    reply SMTP khớp và event ghi SMTP với detect_method="payload". Chống được ca
    này cần ghép luồng TCP (ngoài phạm vi, A2); điều bài này làm được là ghi rõ
    kết luận dựa trên payload để người đọc log biết mà đối chiếu."""
    assert http(sport=80, dport=40470, payload=b"404 page not found\n") == (
        Detection("SMTP", "payload"))


def test_adding_smtp_did_not_change_http_or_dns_detection():
    """Hồi quy của NFR-6: registry dài ra nhưng hai giao thức cũ không đổi."""
    assert http() == Detection("HTTP", "port+payload")
    assert http(dport=8081) == Detection("HTTP", "payload")
    assert dns() == Detection("DNS", "port+payload")
    assert dns(dport=MDNS_PORT) == Detection("DNS", "payload")
