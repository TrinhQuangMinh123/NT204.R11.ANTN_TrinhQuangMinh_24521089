"""T2.5 — process_frame(): tầng liên kết + lưới an toàn (I-1, REQ-14.1, 15.2)."""
import json
import random

import pytest

import struct

from idps.core.frame import RawFrame
from idps.decode import pipeline
from idps.decode.pipeline import process_frame

DST = bytes.fromhex("02420a14000a")
SRC = bytes.fromhex("02420a0a000a")
LINKTYPE_LINUX_SLL = 113

SRC_IP = "10.10.0.10"        # attacker
DST_IP = "10.20.0.10"        # victim
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
SYN, ACK, PSH = 0x02, 0x10, 0x08


def eth(ethertype=0x0800, payload=b""):
    return DST + SRC + ethertype.to_bytes(2, "big") + payload


def raw_ip(s):
    return bytes(int(part) for part in s.split("."))


def ipv4(payload=b"", proto=PROTO_TCP, ihl=5, total_length=None, flags=0,
         frag_offset=0, src=SRC_IP, dst=DST_IP, options=b""):
    """Packet IPv4 dựng tay — xem lý do không dùng Scapy ở tests/test_ipv4.py."""
    header_len = ihl * 4
    if total_length is None:
        total_length = header_len + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s", (4 << 4) | ihl, 0, total_length, 0x1234,
        flags | frag_offset, 64, proto, 0, raw_ip(src), raw_ip(dst),
    ) + options + payload


def tcp(src_port=54321, dst_port=80, flags=SYN, data_offset=5, options=b"",
        payload=b""):
    return struct.pack("!HHIIBBHHH", src_port, dst_port, 0x11223344, 0,
                       data_offset << 4, flags, 64240, 0, 0) + options + payload


def udp(src_port=41234, dst_port=53, length=None, payload=b""):
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def frame_tcp(**kw):
    """Frame Ethernet/IPv4/TCP hoàn chỉnh."""
    return frame(eth(0x0800, ipv4(tcp(**kw), proto=PROTO_TCP)))


def frame_udp(**kw):
    return frame(eth(0x0800, ipv4(udp(**kw), proto=PROTO_UDP)))


def frame(data=b"", linktype=1, truncated=False, source="pcap"):
    return RawFrame(
        data=data,
        ts_sec=1790486523,
        ts_usec=123456,
        wire_len=len(data),
        linktype=linktype,
        source=source,
        truncated=truncated,
    )


# --- I-1: không bao giờ ném --------------------------------------------------

def test_never_raises(event_keys):
    """500 chuỗi bytes ngẫu nhiên có seed cố định + chuỗi rỗng."""
    rng = random.Random(20260927)   # seed cố định -> chạy lại ra cùng bộ dữ liệu
    payloads = [b""]
    payloads += [
        bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        for _ in range(500)
    ]
    for i, data in enumerate(payloads, start=1):
        linktype = rng.choice([1, 1, 1, 113, 0, 65535])
        event = process_frame(frame(data, linktype=linktype), i)
        assert tuple(event) == event_keys       # I-2 giữ nguyên ở mọi nhánh
        assert event["status"] in {"ok", "unknown", "malformed"}
        json.dumps(event)                          # I-3


def test_empty_data_is_malformed_not_an_exception():
    """V2.2: data rỗng, linktype 1 -> lỗi tầng link, không ném."""
    event = process_frame(frame(b"", linktype=1), 1)
    assert event["status"] == "malformed"
    assert event["errors"][0]["layer"] == "link"
    assert event["ethernet"] is None


# --- linktype chưa hỗ trợ (REQ-17.2) ----------------------------------------

def test_unsupported_linktype():
    event = process_frame(frame(eth(), linktype=LINKTYPE_LINUX_SLL), 1)
    assert event["link_proto"] == "UNKNOWN"
    assert event["status"] == "unknown"
    assert event["errors"] == []        # chưa hỗ trợ != dữ liệu hỏng
    assert event["ethernet"] is None    # không parse tầng trên


# --- EtherType lạ (REQ-17.3, 14.1) ------------------------------------------

def test_arp_keeps_ethernet_fields():
    event = process_frame(frame(eth(0x0806, b"arp")), 1)
    assert event["link_proto"] == "Ethernet"
    assert event["network_proto"] == "UNKNOWN"
    assert event["status"] == "unknown"
    # REQ-14.1: tầng dưới đã parse được thì giữ nguyên
    assert event["ethernet"]["src_mac"] == "02:42:0a:0a:00:0a"
    assert event["ethernet"]["ethertype"] == 0x0806


@pytest.mark.parametrize("ethertype", [0x86DD, 0x8100, 0x0842, 0x0000])
def test_other_ethertypes_are_unknown(ethertype):
    event = process_frame(frame(eth(ethertype)), 1)
    assert event["network_proto"] == "UNKNOWN"


def test_ipv4_ethertype_reaches_network_layer():
    """EtherType 0x0800 -> network_proto là IPv4 (T5.4 nối parser vào đây)."""
    event = process_frame(frame_tcp(), 1)
    assert event["link_proto"] == "Ethernet"
    assert event["network_proto"] == "IPv4"
    assert event["status"] == "ok"
    assert event["errors"] == []


# --- frame cụt (REQ-15.2) ----------------------------------------------------

def test_short_frame_reports_link_layer():
    event = process_frame(frame(b"\x00" * 13), 1)
    assert event["status"] == "malformed"
    assert [e["layer"] for e in event["errors"]] == ["link"]
    assert "13" in event["errors"][0]["reason"]
    assert event["network_proto"] is None   # dừng đi lên


# --- bản ghi bị cắt (REQ-2.5) ------------------------------------------------

def test_truncated_record_still_parses_what_it_has():
    event = process_frame(frame(eth(0x0800, ipv4(tcp())), truncated=True), 1)
    assert event["errors"] == [{"layer": "capture", "reason": "truncated record"}]
    assert event["ethernet"] is not None     # vẫn parse phần đọc được
    assert event["network_proto"] == "IPv4"
    assert event["src_ip"] == SRC_IP          # REQ-2.5: parse hết phần đọc được
    assert event["tcp"]["flags"] == ["SYN"]
    assert event["status"] == "malformed"     # vì bản ghi bị cắt


def test_truncated_and_short_gives_two_errors():
    event = process_frame(frame(b"\x00" * 5, truncated=True), 1)
    assert [e["layer"] for e in event["errors"]] == ["capture", "link"]


# --- lưới an toàn (REQ-15.3) -------------------------------------------------

def test_internal_error_when_a_parser_raises(monkeypatch, event_keys):
    def boom(linktype, data):
        raise ValueError("parser gia no tung")

    monkeypatch.setattr(pipeline, "parse_link", boom)
    event = process_frame(frame(eth()), 1)
    assert event["errors"] == [
        {"layer": "internal", "reason": "ValueError: parser gia no tung"}
    ]
    assert event["status"] == "malformed"
    assert tuple(event) == event_keys


def test_internal_error_keeps_fields_parsed_before_the_crash(monkeypatch):
    real = pipeline.link_name

    def boom(linktype):
        real(linktype)
        raise RuntimeError("sau khi da parse xong link")

    monkeypatch.setattr(pipeline, "link_name", boom)
    event = process_frame(frame(eth()), 1)
    assert event["errors"][0]["layer"] == "internal"
    assert event["cap_len"] == 14           # phần dựng trước đó còn nguyên


# --- siêu dữ liệu chung ------------------------------------------------------

def test_metadata_comes_from_the_frame():
    event = process_frame(frame(eth(), source="live"), 42)
    assert event["packet_id"] == 42
    assert event["source"] == "live"
    assert event["timestamp"] == "2026-09-27T05:22:03.123456Z"
    assert event["cap_len"] == 14 and event["wire_len"] == 14


# --- T5.4: 5-tuple đầy đủ qua cả bốn tầng (C-4, REQ-4.3, 4.4, 14.1, 15.2) ---

def test_tcp_packet_fills_the_five_tuple():
    event = process_frame(frame_tcp(src_port=54321, dst_port=80,
                                    payload=b"GET / HTTP/1.1\r\n\r\n"), 1)
    assert event["status"] == "ok" and event["errors"] == []
    assert event["network_proto"] == "IPv4"
    assert event["transport_proto"] == "TCP"
    assert (event["src_ip"], event["dst_ip"]) == (SRC_IP, DST_IP)
    assert (event["src_port"], event["dst_port"]) == (54321, 80)
    assert event["tcp"]["flags"] == ["SYN"]
    assert event["udp"] is None                  # chỉ một khoá transport được điền


def test_udp_packet_fills_the_five_tuple():
    event = process_frame(frame_udp(src_port=41234, dst_port=53,
                                    payload=b"\x12\x34"), 1)
    assert event["status"] == "ok"
    assert event["transport_proto"] == "UDP"
    assert (event["src_port"], event["dst_port"]) == (41234, 53)
    assert event["udp"]["length"] == 10
    assert event["tcp"] is None


def test_ipv4_keys_match_design_and_do_not_repeat_the_addresses():
    """src_ip/dst_ip chỉ ở top-level (A.1), không lặp lại trong khoá "ipv4"."""
    event = process_frame(frame_tcp(), 1)
    assert tuple(event["ipv4"]) == (
        "version", "ihl", "total_length", "identification", "df", "mf",
        "fragment_offset", "ttl", "protocol", "is_fragment",
    )
    assert "src_ip" not in event["ipv4"]


def test_ihl_with_options_still_finds_the_transport_header():
    """REQ-4.2: header IPv4 24 byte -> TCP bắt đầu ở byte 24, không phải 20."""
    event = process_frame(
        frame(eth(0x0800, ipv4(tcp(dst_port=8081), ihl=6,
                               options=bytes.fromhex("94040000")))), 1)
    assert event["status"] == "ok"
    assert event["ipv4"]["ihl"] == 6
    assert event["dst_port"] == 8081


def test_ethernet_padding_does_not_leak_into_the_payload():
    """Frame ngắn bị đệm lên 60 byte: phần đệm không được thành payload TCP."""
    packet = ipv4(tcp(payload=b"hi"), proto=PROTO_TCP)
    event = process_frame(frame(eth(0x0800, packet + b"\x00" * 18)), 1)
    assert event["status"] == "ok"
    assert event["tcp"]["payload_len"] == 2


# --- protocol chưa hỗ trợ (REQ-4.1, 14.1) -----------------------------------

def test_icmp_is_unknown_transport_but_keeps_the_ip_fields():
    """Ping trong lab: IPv4 đọc xong, transport chưa hỗ trợ -> unknown."""
    event = process_frame(frame(eth(0x0800, ipv4(b"\x08\x00echo",
                                                 proto=PROTO_ICMP))), 1)
    assert event["transport_proto"] == "UNKNOWN"
    assert event["status"] == "unknown"
    assert event["errors"] == []                 # chưa hỗ trợ != dữ liệu hỏng
    assert event["src_ip"] == SRC_IP             # REQ-14.1
    assert event["dst_ip"] == DST_IP
    assert event["ipv4"]["protocol"] == PROTO_ICMP
    assert event["tcp"] is None and event["udp"] is None
    assert event["src_port"] is None and event["dst_port"] is None


@pytest.mark.parametrize("proto", [2, 41, 47, 50, 89, 132, 255])
def test_other_ip_protocols_are_unknown(proto):
    event = process_frame(frame(eth(0x0800, ipv4(b"body", proto=proto))), 1)
    assert event["transport_proto"] == "UNKNOWN"
    assert event["status"] == "unknown"


# --- IPv4 hỏng: dừng đi lên (REQ-4.3, §4.2) ---------------------------------

def test_short_ipv4_is_malformed_and_stops_before_transport():
    """IPv4 cụt (12 byte): status malformed, khoá tcp còn null."""
    event = process_frame(frame(eth(0x0800, b"\x45\x00" + b"\x00" * 10)), 1)
    assert event["status"] == "malformed"
    assert [e["layer"] for e in event["errors"]] == ["ipv4"]
    assert event["network_proto"] == "IPv4"      # EtherType đã nói là IPv4
    assert event["ipv4"] is None                 # chưa đọc nổi header
    assert event["tcp"] is None
    assert event["transport_proto"] is None
    assert event["src_ip"] is None


def test_bad_ihl_keeps_the_ip_fields_it_managed_to_read():
    """IHL=3: lỗi, nhưng địa chỉ đã đọc được thì vẫn ghi (REQ-14.1)."""
    event = process_frame(frame(eth(0x0800, ipv4(tcp(), ihl=3))), 1)
    assert event["status"] == "malformed"
    assert event["errors"][0]["layer"] == "ipv4"
    assert "ihl=3" in event["errors"][0]["reason"]
    assert event["src_ip"] == SRC_IP
    assert event["ipv4"]["ihl"] == 3
    assert event["tcp"] is None                  # không parse tầng trên


def test_total_length_longer_than_data_is_malformed():
    event = process_frame(frame(eth(0x0800, ipv4(tcp(), total_length=200))), 1)
    assert event["status"] == "malformed"
    assert event["errors"][0]["layer"] == "ipv4"
    assert event["tcp"] is None


# --- mảnh IPv4 (REQ-4.4) ----------------------------------------------------

def test_non_first_fragment_does_not_parse_transport():
    """Mảnh thứ hai: byte đầu là dữ liệu, không phải header TCP."""
    event = process_frame(
        frame(eth(0x0800, ipv4(b"\x00" * 24, proto=PROTO_TCP, frag_offset=185))), 1)
    assert event["errors"] == []                 # mảnh không phải lỗi
    assert event["ipv4"]["is_fragment"] is True
    assert event["ipv4"]["fragment_offset"] == 185
    assert event["transport_proto"] is None      # không đoán tầng transport
    assert event["tcp"] is None
    assert event["src_port"] is None
    assert event["src_ip"] == SRC_IP             # vẫn biết ai gửi cho ai


def test_first_fragment_still_parses_transport():
    """MF=1 nhưng offset=0: mảnh ĐẦU vẫn chứa header TCP nguyên vẹn."""
    event = process_frame(
        frame(eth(0x0800, ipv4(tcp(dst_port=80), proto=PROTO_TCP,
                               flags=0x2000))), 1)
    assert event["ipv4"]["is_fragment"] is True
    assert event["ipv4"]["mf"] is True
    assert event["transport_proto"] == "TCP"     # khác hẳn ca mảnh thứ hai
    assert event["dst_port"] == 80


# --- TCP/UDP hỏng: tên tầng là tên giao thức (REQ-15.2, V5.2) ---------------

def test_bad_tcp_data_offset_reports_layer_tcp():
    """V5.2: data offset=15 trên segment 20 byte -> layer "tcp", KHÔNG internal."""
    event = process_frame(frame_tcp(data_offset=15), 1)
    assert event["status"] == "malformed"
    assert [e["layer"] for e in event["errors"]] == ["tcp"]
    assert "internal" not in [e["layer"] for e in event["errors"]]
    assert event["transport_proto"] == "TCP"     # protocol number vẫn nói là TCP
    assert event["tcp"]["src_port"] == 54321     # port và cờ vẫn giữ (REQ-14.1)
    assert event["tcp"]["flags"] == ["SYN"]
    assert event["tcp"]["payload_len"] == 0


def test_bad_udp_length_reports_layer_udp():
    event = process_frame(frame_udp(length=99, payload=b"abc"), 1)
    assert event["status"] == "malformed"
    assert [e["layer"] for e in event["errors"]] == ["udp"]
    assert event["udp"]["dst_port"] == 53
    assert event["src_port"] == 41234


def test_ipv4_with_empty_transport_payload_is_malformed():
    """total_length = chỉ header IPv4: không còn byte nào cho header TCP."""
    event = process_frame(frame(eth(0x0800, ipv4(b"", proto=PROTO_TCP))), 1)
    assert event["status"] == "malformed"
    assert event["errors"][0]["layer"] == "tcp"


def test_handshake_is_distinguishable_end_to_end():
    """TC-01 ở mức pipeline: ba event chỉ khác nhau ở trường flags."""
    flags = [
        process_frame(frame_tcp(flags=f), i)["tcp"]["flags"]
        for i, f in enumerate([SYN, SYN | ACK, ACK], start=1)
    ]
    assert flags == [["SYN"], ["SYN", "ACK"], ["ACK"]]


# --- T6.4: detector + parser app (C-4, REQ-10.4, 14.1, 15.4, ADR-14) --------

GET_80 = b"GET / HTTP/1.1\r\nHost: 10.20.0.10\r\nUser-Agent: curl/8.14.1\r\n\r\n"
RESP_80 = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 3\r\n\r\nhi\n"


def test_http_request_on_port_80():
    event = process_frame(frame_tcp(dst_port=80, flags=PSH | ACK,
                                    payload=GET_80), 1)
    assert event["status"] == "ok" and event["errors"] == []
    assert event["app_proto"] == "HTTP"
    assert event["detect_method"] == "port+payload"
    assert event["app"]["kind"] == "request"
    assert event["app"]["method"] == "GET"
    assert event["app"]["uri"] == "/"
    assert event["app"]["headers"][0] == ["Host", "10.20.0.10"]


def test_http_response_on_port_80():
    event = process_frame(frame_tcp(src_port=80, dst_port=40470,
                                    flags=PSH | ACK, payload=RESP_80), 1)
    assert event["app_proto"] == "HTTP"
    assert event["detect_method"] == "port+payload"   # sport=80 cũng tính
    assert event["app"]["kind"] == "response"
    assert event["app"]["status_code"] == 200
    assert event["app"]["method"] is None


def test_http_on_nonstandard_port_8081():
    """TC-13/REQ-11.1 ở mức pipeline: chỉ payload cứu được nhận diện."""
    event = process_frame(frame_tcp(dst_port=8081, flags=PSH | ACK,
                                    payload=GET_80), 1)
    assert event["app_proto"] == "HTTP"
    assert event["detect_method"] == "payload"
    assert event["app"]["method"] == "GET"
    assert event["status"] == "ok"


# --- REQ-15.4: payload rỗng ---------------------------------------------------

def test_empty_payload():
    """Packet ACK trắng của handshake: app_proto null, KHÔNG phải lỗi."""
    event = process_frame(frame_tcp(flags=ACK), 1)
    assert event["tcp"]["payload_len"] == 0
    assert event["app_proto"] is None
    assert event["detect_method"] is None
    assert event["app"] is None
    assert event["errors"] == [] and event["status"] == "ok"


# --- payload lạ: UNKNOWN nhưng status vẫn ok (ADR-14, §5.4) ------------------

def test_unknown_payload_keeps_status_ok():
    event = process_frame(frame_tcp(dst_port=80, flags=PSH | ACK,
                                    payload=b"\x16\x03\x01\x02\x00rubbish"), 1)
    assert event["app_proto"] == "UNKNOWN"
    assert event["detect_method"] is None
    assert event["app"] is None                  # ADR-14
    assert event["errors"] == []
    # app_proto="UNKNOWN" KHÔNG làm status thành unknown: packet đã parse xong
    # tới hết tầng transport, chỉ là bài 1 chưa biết giao thức ứng dụng này.
    assert event["status"] == "ok"


def test_payload_shorter_than_the_dns_header_is_unknown():
    """4 byte trên port 53: ngắn hơn header DNS (12 byte) -> UNKNOWN, không lỗi.

    Trước T8.2 ca này ra UNKNOWN vì registry chưa có DNS; bây giờ nó ra UNKNOWN
    vì đúng điều kiện đầu của chữ ký Phụ lục C. Cùng kết quả, khác lý do — nên
    tên test được sửa theo lý do mới (như T4.3 đã làm với test của chế độ live).
    """
    event = process_frame(frame_udp(dst_port=53, payload=b"\x12\x34\x01\x00"), 1)
    assert event["app_proto"] == "UNKNOWN"
    assert event["app"] is None and event["errors"] == []


def test_http_signature_over_udp_is_unknown():
    """HTTP đăng ký ở TCP: cùng bytes đó trên UDP không được gán HTTP."""
    event = process_frame(frame_udp(dst_port=80, payload=GET_80), 1)
    assert event["app_proto"] == "UNKNOWN"


# --- V6.2: parser app báo lỗi -> layer "http", chương trình chạy tiếp --------

def test_bad_http_header_reports_layer_http():
    payload = b"GET / HTTP/1.1\r\nHost: 10.20.0.10\r\nX: caf\xff\r\n\r\n"
    event = process_frame(frame_tcp(dst_port=80, flags=PSH | ACK,
                                    payload=payload), 1)
    assert [e["layer"] for e in event["errors"]] == ["http"]
    assert "decode" in event["errors"][0]["reason"]
    assert event["status"] == "malformed"
    # Nhận diện vẫn thành công, và app giữ phần đã parse được (§5.4)
    assert event["app_proto"] == "HTTP"
    assert event["app"]["method"] == "GET"
    assert event["app"]["headers"] == [["Host", "10.20.0.10"]]
    # REQ-14.1: các tầng dưới không bị ảnh hưởng
    assert event["src_ip"] == SRC_IP and event["dst_port"] == 80


def test_incomplete_http_is_not_an_error():
    """REQ-7.4: header tràn sang segment sau -> cờ incomplete, không phải lỗi."""
    event = process_frame(frame_tcp(dst_port=80, flags=ACK,
                                    payload=b"GET / HTTP/1.1\r\nHos"), 1)
    assert event["errors"] == [] and event["status"] == "ok"
    assert event["app"]["incomplete"] is True


# --- tầng dưới dừng thì tầng app không được chạy -----------------------------

def test_transport_error_stops_before_detection():
    event = process_frame(frame_tcp(data_offset=15), 1)
    assert event["app_proto"] is None and event["app"] is None


def test_icmp_never_reaches_the_detector():
    event = process_frame(frame(eth(0x0800, ipv4(b"\x08\x00GET / HTTP/1.1 ",
                                                 proto=PROTO_ICMP))), 1)
    assert event["transport_proto"] == "UNKNOWN"
    assert event["app_proto"] is None            # không đoán khi chưa biết port


def test_non_first_fragment_never_reaches_the_detector():
    """Byte đầu của mảnh thứ hai là dữ liệu, không phải header TCP."""
    event = process_frame(
        frame(eth(0x0800, ipv4(b"GET / HTTP/1.1\r\n\r\n" + b"\x00" * 6,
                               proto=PROTO_TCP, frag_offset=185))), 1)
    assert event["app_proto"] is None and event["app"] is None


# --- app_proto và app luôn nhất quán với nhau (ADR-14, I-2) ------------------

def test_app_is_null_whenever_app_proto_is_not_a_real_protocol():
    rng = random.Random(20260928)
    for i in range(300):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        event = process_frame(frame_tcp(dst_port=rng.choice([80, 8081, 25]),
                                        payload=payload), i + 1)
        if event["app_proto"] in (None, "UNKNOWN"):
            assert event["app"] is None
        else:
            assert event["app"] is not None
            assert event["detect_method"] in {"port+payload", "payload"}


# --- T8.1/T8.2: DNS đi hết pipeline (REQ-8.1-8.5, REQ-14.1, ADR-14) ----------

def dns_header(ident=0x1234, flags=0x0100, qdcount=1, ancount=0):
    return struct.pack("!HHHHHH", ident, flags, qdcount, ancount, 0, 0)


DNS_NAME = b"\x06victim\x03lab\x00"          # 12 byte, đặt ở offset 12
DNS_QUESTION = DNS_NAME + struct.pack("!HH", 1, 1)      # hết ở offset 28
# Answer A hợp lệ: tên nén trỏ về question, TTL 300, RDATA 10.20.0.10.
DNS_ANSWER_A = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, 20, 0, 10])
DNS_QUERY = dns_header() + DNS_QUESTION
DNS_RESPONSE = dns_header(flags=0x8180, ancount=1) + DNS_QUESTION + DNS_ANSWER_A


def test_dns_query_through_the_pipeline():
    """Query trên UDP 53 -> app_proto DNS, app đầy đủ, status ok (REQ-8.1)."""
    event = process_frame(frame_udp(dst_port=53, payload=DNS_QUERY), 1)
    assert event["transport_proto"] == "UDP"
    assert (event["app_proto"], event["detect_method"]) == ("DNS", "port+payload")
    assert event["app"]["qr"] == "query"
    assert event["app"]["questions"] == [{"name": "victim.lab", "type": "A"}]
    assert event["status"] == "ok" and event["errors"] == []


def test_dns_response_through_the_pipeline():
    """Response từ server (sport=53) -> answer có name giải từ con trỏ (REQ-8.2)."""
    event = process_frame(frame_udp(src_port=53, dst_port=41234,
                                    payload=DNS_RESPONSE), 1)
    assert (event["app_proto"], event["detect_method"]) == ("DNS", "port+payload")
    assert event["app"]["answers"] == [
        {"name": "victim.lab", "type": "A", "ttl": 300, "data": "10.20.0.10"},
    ]
    assert event["status"] == "ok"


def test_dns_on_nonstandard_port_through_the_pipeline():
    """REQ-11.2: cùng message đó trên port 5353 -> vẫn DNS, nhưng detect khác."""
    event = process_frame(frame_udp(dst_port=5353, payload=DNS_QUERY), 1)
    assert (event["app_proto"], event["detect_method"]) == ("DNS", "payload")


@pytest.mark.parametrize("bad_name, label", [
    (struct.pack("!H", 0xC000 | 28), "con trỏ tự trỏ vào chính nó"),
    (struct.pack("!H", 0xC000 | 9999), "con trỏ ra ngoài payload"),
])
def test_bad_pointer_in_an_answer_makes_the_event_malformed(bad_name, label):
    """REQ-8.4 ở mức event: lỗi tầng dns, KHÔNG có internal, giữ question."""
    payload = (dns_header(flags=0x8180, ancount=1) + DNS_QUESTION + bad_name
               + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, 20, 0, 10]))
    event = process_frame(frame_udp(src_port=53, dst_port=41234,
                                    payload=payload), 1)
    assert event["status"] == "malformed", label
    assert [e["layer"] for e in event["errors"]] == ["dns"]
    # ADR-4: packet hỏng đi đường ParseResult.error, không phải exception.
    assert "internal" not in [e["layer"] for e in event["errors"]]
    # REQ-14.1: những gì đã parse được vẫn còn trong event.
    assert event["app_proto"] == "DNS"
    assert event["app"]["questions"] == [{"name": "victim.lab", "type": "A"}]
    assert event["src_port"] == 53 and event["dst_port"] == 41234


def test_ancount_larger_than_actual_keeps_the_parsed_answer():
    """REQ-8.5 ở mức event: ANCOUNT=5, 1 answer thật -> malformed + giữ answer."""
    payload = (dns_header(flags=0x8180, ancount=5) + DNS_QUESTION + DNS_ANSWER_A)
    event = process_frame(frame_udp(src_port=53, dst_port=41234,
                                    payload=payload), 1)
    assert event["status"] == "malformed"
    assert [e["layer"] for e in event["errors"]] == ["dns"]
    assert event["app"]["ancount"] == 5                  # con số bên gửi khai
    assert len(event["app"]["answers"]) == 1             # bản ghi đọc được
    assert event["app"]["answers"][0]["data"] == "10.20.0.10"


@pytest.mark.parametrize("bad_name", [
    struct.pack("!H", 0xC000 | 12),                      # tự trỏ vào chính nó
    struct.pack("!H", 0xC000 | 9999),                    # ra ngoài payload
])
def test_bad_pointer_in_the_question_is_unknown_not_malformed(bad_name):
    """Ranh giới ĐÃ CHỐT: con trỏ xấu trong QUESTION -> UNKNOWN, không malformed.

    Chữ ký DNS của Phụ lục C là "toàn bộ phần question parse được". Nếu chính
    phần question hỏng thì `matches_dns()` trả False -> detector không gán DNS,
    nên không có parser nào chạy và không có lỗi nào để ghi: event là
    `app_proto="UNKNOWN"`, `status="ok"`.

    Nói cách khác, REQ-8.4 ("đánh dấu malformed") chỉ có hiệu lực khi message đã
    được NHẬN DIỆN là DNS — tức con trỏ xấu nằm ở answer hoặc trong RDATA của
    CNAME/NS/PTR (hai test ngay trên).

    Quyết định (2026-09-27, design.md ADR-5 mục "Ranh giới đã chốt"): giữ
    `UNKNOWN`, KHÔNG sửa thành `malformed`, vì đổi nhãn không giải quyết bài toán
    nào:
      * `status` là nhãn phân loại; tính chất an toàn của REQ-8.4 (dừng ngay,
        không treo, không lỗi `internal`) đã đúng ở ca này — con trỏ vòng lặp bị
        phát hiện ngay trong `question_section_fits()`, là điều test này khẳng
        định bằng việc event tồn tại và `errors` rỗng.
      * Event không mất bằng chứng: `udp.payload_b64` giữ đủ bytes (I-4), và
        `app_proto="UNKNOWN"` trên port 53 tự nó là tín hiệu đáng viết luật.
      * `malformed` nghĩa là "một parser thấy mâu thuẫn trong dữ liệu thuộc tầng
        của nó"; ở đây không parser nào nhận payload này.
      * Giá phải trả để đổi nhãn: nới chữ ký thành "header + QDCOUNT >= 1" ->
        gần như mọi payload UDP >= 12 byte bị gán DNS (rủi ro R5).
    """
    payload = dns_header() + bad_name + struct.pack("!HH", 1, 1)
    event = process_frame(frame_udp(dst_port=53, payload=payload), 1)
    assert event["app_proto"] == "UNKNOWN"
    assert event["detect_method"] is None
    assert event["app"] is None
    assert event["status"] == "ok" and event["errors"] == []
