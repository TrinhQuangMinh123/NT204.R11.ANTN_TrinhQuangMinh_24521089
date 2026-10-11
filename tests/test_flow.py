"""Phase 3 — Flow/Connection Tracker. Event dựng tay, không qua parser (NFR-16).

T3.1: khoá hai chiều + flow_id. Các task sau thêm test vào cuối file này.
"""
import json

from idps.core.event import new_event
from idps.core.frame import RawFrame
from idps.process.config import Config
from idps.process.flow import FlowTracker

CFG = Config.load()


def make_event(src, sport, dst, dport, proto="TCP", packet_id=1, ts=1_000_000):
    """Event tối thiểu: đúng những field Flow Tracker đọc (đã qua Preprocessor)."""
    event = new_event(RawFrame(b"\x00" * 14, 1790486523, 0, 60, 1, "pcap"), packet_id)
    event["transport_proto"] = proto
    event["src_ip"], event["dst_ip"] = src, dst
    event["src_port"], event["dst_port"] = sport, dport
    event["preprocess"].update(
        transport_proto=proto, src_ip=src, dst_ip=dst, status="valid", action="forwarded",
        ts_usec=ts,
    )
    return event


def tcp_event(src, sport, dst, dport, flags, payload_len=0, ts=1_000_000):
    event = make_event(src, sport, dst, dport, ts=ts)
    event["tcp"] = {"src_port": sport, "dst_port": dport, "flags": list(flags),
                    "payload_len": payload_len}
    return event


def feed(tracker, *packets):
    """Đưa từng packet (c=client A→B, s=server B→A, cờ) vào tracker; trả các event."""
    events = []
    for n, (side, flags) in enumerate(packets):
        if side == "c":
            event = tcp_event(A, 5000, B, 80, flags, ts=1_000_000 + n)
        else:
            event = tcp_event(B, 80, A, 5000, flags, ts=1_000_000 + n)
        tracker.process(event)
        events.append(event)
    return events


def states(events):
    return [e["flow"]["state"] for e in events]


A, B = "10.10.0.10", "10.20.0.10"


def test_bidirectional():
    tracker = FlowTracker(CFG)
    out = make_event(A, 5000, B, 80)          # A -> B
    back = make_event(B, 80, A, 5000)         # B -> A
    again = make_event(A, 5000, B, 80)
    for event in (out, back, again):
        tracker.process(event)
    assert out["flow"]["flow_id"] == back["flow"]["flow_id"] == again["flow"]["flow_id"] == 1
    assert out["flow"]["direction"] == "forward"
    assert back["flow"]["direction"] == "backward"
    assert again["flow"]["direction"] == "forward"
    assert len(tracker.table) == 1


def test_endpoint_a_is_first_packet_source():
    # Chiều thuận = chiều của packet ĐẦU TIÊN, dù IP nhỏ hơn hay lớn hơn.
    tracker = FlowTracker(CFG)
    first = make_event(B, 80, A, 5000)        # B có IP "lớn" hơn nhưng đến trước
    reply = make_event(A, 5000, B, 80)
    tracker.process(first)
    tracker.process(reply)
    assert first["flow"]["direction"] == "forward"
    assert reply["flow"]["direction"] == "backward"


def test_no_merge():
    tracker = FlowTracker(CFG)
    events = [
        make_event(A, 5000, B, 80),           # gốc
        make_event(A, 5001, B, 80),           # khác port nguồn
        make_event(A, 5000, B, 81),           # khác port đích
        make_event(A, 5000, "10.20.0.11", 80),  # khác endpoint
        make_event(A, 5000, B, 80, proto="UDP"),  # khác protocol
    ]
    for event in events:
        tracker.process(event)
    ids = [e["flow"]["flow_id"] for e in events]
    assert ids == [1, 2, 3, 4, 5]
    assert len(tracker.table) == 5


def test_normalized_ip_does_not_split_flow():
    tracker = FlowTracker(CFG)
    plain = make_event(A, 5000, B, 80)
    padded = make_event("010.010.000.010", 5000, "010.020.000.010", 80)
    padded["preprocess"]["src_ip"] = "10.10.0.10"   # Preprocessor đã chuẩn hoá
    padded["preprocess"]["dst_ip"] = "10.20.0.10"
    tracker.process(plain)
    tracker.process(padded)
    assert plain["flow"]["flow_id"] == padded["flow"]["flow_id"]


def test_flow_id_stable():
    def run():
        tracker = FlowTracker(CFG)
        events = [make_event(A, 5000, B, 80), make_event(B, 80, A, 5000),
                  make_event(A, 6000, B, 53, proto="UDP"), make_event(A, 5000, B, 80)]
        for event in events:
            tracker.process(event)
        return [e["flow"]["flow_id"] for e in events]
    assert run() == run() == [1, 1, 2, 1]


def test_no_five_tuple():
    tracker = FlowTracker(CFG)
    cases = {
        "src_port": make_event(A, None, B, 80),
        "dst_port": make_event(A, 5000, B, None),
        "transport": make_event(A, 5000, B, 80, proto="UNKNOWN"),
    }
    cases["src_ip"] = make_event(None, 5000, B, 80)
    for name, event in cases.items():
        assert tracker.process(event) is True, name           # không chặn, không ném
        assert event["flow"]["flow_id"] is None, name
        assert event["flow"]["direction"] is None, name
        assert event["flow"]["reasons"], name
    assert len(tracker.table) == 0                            # không tạo flow nào
    ok = make_event(A, 5000, B, 80)
    tracker.process(ok)
    assert ok["flow"]["flow_id"] == 1                         # bộ đếm không bị tiêu


# --- T3.2 máy trạng thái TCP (Phụ lục I.1) — một test mỗi dòng ---------------

def test_syn_starts_handshake():
    tracker = FlowTracker(CFG)
    [syn] = feed(tracker, ("c", ["SYN"]))
    assert syn["flow"]["state"] == "HANDSHAKE"
    assert tracker.table.flows()[0].midstream is False


def test_synack_stays_handshake():
    tracker = FlowTracker(CFG)
    assert states(feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]))) == \
        ["HANDSHAKE", "HANDSHAKE"]
    assert tracker.table.flows()[0].seen_synack is True


def test_forward_ack_after_synack_establishes():
    tracker = FlowTracker(CFG)
    events = feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]), ("c", ["ACK"]))
    assert states(events) == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]


def test_ack_without_synack_does_not_establish():
    # SYN rồi ACK suông chiều thuận mà chưa có SYN/ACK trả lời -> chưa là kết nối.
    tracker = FlowTracker(CFG)
    assert states(feed(tracker, ("c", ["SYN"]), ("c", ["ACK"]))) == ["HANDSHAKE"] * 2


def test_backward_ack_does_not_establish():
    tracker = FlowTracker(CFG)
    events = feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]), ("s", ["ACK"]))
    assert states(events)[-1] == "HANDSHAKE"


def test_fin_moves_to_closing():
    tracker = FlowTracker(CFG)
    events = feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]), ("c", ["ACK"]),
                  ("c", ["FIN", "ACK"]))
    assert states(events)[-1] == "CLOSING"


def test_fin_both_ways_then_ack_closes():
    tracker = FlowTracker(CFG)
    events = feed(tracker, ("c", ["ACK"]), ("c", ["FIN", "ACK"]), ("s", ["ACK"]),
                  ("s", ["FIN", "ACK"]), ("c", ["ACK"]))
    # ACK của server sau FIN đầu (mới một chiều FIN) KHÔNG đóng; FIN thứ hai cũng
    # chưa; chỉ ACK sau FIN cuối mới CLOSED.
    assert states(events) == ["ESTABLISHED", "CLOSING", "CLOSING", "CLOSING", "CLOSED"]


def test_one_sided_fin_never_closes():
    tracker = FlowTracker(CFG)
    events = feed(tracker, ("c", ["ACK"]), ("c", ["FIN", "ACK"]),
                  ("c", ["ACK"]), ("s", ["ACK"]))
    assert states(events)[-1] == "CLOSING"


def test_rst_resets_from_any_state():
    for opening in ([("c", ["SYN"])],                                # HANDSHAKE
                    [("c", ["ACK"])],                                # ESTABLISHED
                    [("c", ["ACK"]), ("c", ["FIN", "ACK"])]):        # CLOSING
        tracker = FlowTracker(CFG)
        events = feed(tracker, *opening, ("s", ["RST"]))
        assert states(events)[-1] == "RESET", opening


def test_midstream_first_packet_is_established():
    tracker = FlowTracker(CFG)
    [first] = feed(tracker, ("c", ["ACK"]))
    assert first["flow"]["state"] == "ESTABLISHED"
    assert tracker.table.flows()[0].midstream is True


def test_first_synack_is_midstream_not_handshake():
    tracker = FlowTracker(CFG)
    [first] = feed(tracker, ("c", ["SYN", "ACK"]))
    assert first["flow"]["state"] == "ESTABLISHED"
    assert tracker.table.flows()[0].midstream is True


def test_empty_payload_still_updates_last_seen():
    tracker = FlowTracker(CFG)
    events = feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]), ("c", ["ACK"]))
    flow = tracker.table.flows()[0]
    assert all(e["tcp"]["payload_len"] == 0 for e in events)
    assert flow.start_usec == 1_000_000
    assert flow.last_seen_usec == 1_000_002           # đổi theo từng packet rỗng


def test_closed_absorbs_retransmitted_fin_and_ack():
    tracker = FlowTracker(CFG)
    events = feed(tracker, ("c", ["ACK"]), ("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"]),
                  ("c", ["ACK"]), ("s", ["FIN", "ACK"]), ("c", ["ACK"]))
    assert states(events)[3:] == ["CLOSED", "CLOSED", "CLOSED"]
    assert len({e["flow"]["flow_id"] for e in events}) == 1   # không đẻ flow mới


# --- T3.3 flow UDP (Phụ lục I.2) ---------------------------------------------

def udp_event(src, sport, dst, dport, wire_len=70, status="ok", ts=1_000_000):
    event = make_event(src, sport, dst, dport, proto="UDP", ts=ts)
    event["wire_len"], event["cap_len"], event["status"] = wire_len, wire_len, status
    return event


def test_udp_query_response_is_one_active_flow():
    tracker = FlowTracker(CFG)
    query = udp_event(A, 40000, B, 53, wire_len=74)
    response = udp_event(B, 53, A, 40000, wire_len=90)
    tracker.process(query)
    tracker.process(response)
    flow = tracker.table.flows()[0]
    assert len(tracker.table) == 1
    assert query["flow"]["flow_id"] == response["flow"]["flow_id"]
    assert query["flow"]["state"] == response["flow"]["state"] == "ACTIVE"
    assert flow.packet_count == 2
    assert flow.direction_packets == {"forward": 1, "backward": 1}
    assert flow.direction_bytes == {"forward": 74, "backward": 90}
    assert flow.byte_count == 164


def test_udp_has_no_connection_state():
    tracker = FlowTracker(CFG)
    for _ in range(3):
        tracker.process(udp_event(A, 40000, B, 53))
    flow = tracker.table.flows()[0]
    assert flow.state == "ACTIVE"
    assert flow.midstream is None                  # UDP không có "giữa phiên"
    assert flow.fin_directions == set() and flow.seen_synack is False


def test_udp_malformed_still_counted_with_reason():
    tracker = FlowTracker(CFG)
    good = udp_event(A, 40000, B, 53, wire_len=70)
    bad = udp_event(A, 40000, B, 53, wire_len=60, status="malformed")
    tracker.process(good)
    tracker.process(bad)
    flow = tracker.table.flows()[0]
    assert bad["flow"]["flow_id"] == good["flow"]["flow_id"]
    assert (flow.packet_count, flow.byte_count) == (2, 130)
    assert flow.malformed_packets == 1
    assert "malformed_packet" in bad["flow"]["reasons"]
    assert good["flow"]["reasons"] == []


def test_wire_len_missing_falls_back_to_cap_len():
    tracker = FlowTracker(CFG)
    event = udp_event(A, 40000, B, 53, wire_len=None)
    event["cap_len"] = 55
    tracker.process(event)
    flow = tracker.table.flows()[0]
    assert (flow.packet_count, flow.byte_count) == (1, 55)    # vẫn đếm packet
    assert "wire_len_missing" in event["flow"]["reasons"]


# --- T3.4 thống kê per-flow và hình dạng flow record --------------------------

RECORD_KEYS = [
    "schema_version", "flow_id", "protocol", "application_protocol", "endpoint_a",
    "endpoint_b", "start_time", "last_seen", "close_time", "start_time_usec",
    "last_seen_usec", "duration_usec", "packet_count", "byte_count",
    "forward_packet_count", "forward_byte_count", "backward_packet_count",
    "backward_byte_count", "payload_byte_count", "syn_count", "ack_count",
    "fin_count", "rst_count", "state", "midstream", "close_reason", "mails", "reasons",
]


def close_all(tracker, usec=9_000_000):
    return [f.to_record(usec, "end_of_run") for f in tracker.table.flows()]


def sized(event, wire_len, payload_len=0):
    event["wire_len"] = event["cap_len"] = wire_len
    event["tcp"]["payload_len"] = payload_len
    return event


def test_counts_add_up():
    tracker = FlowTracker(CFG)
    packets = [("c", ["SYN"], 74, 0), ("s", ["SYN", "ACK"], 74, 0), ("c", ["ACK"], 66, 0),
               ("c", ["PSH", "ACK"], 300, 234), ("s", ["ACK"], 66, 0),
               ("s", ["PSH", "ACK"], 500, 434)]
    for n, (side, flags, size, payload) in enumerate(packets):
        src = (A, 5000, B, 80) if side == "c" else (B, 80, A, 5000)
        tracker.process(sized(tcp_event(*src, flags, ts=1_000_000 + n), size, payload))
    [record] = close_all(tracker)
    assert record["packet_count"] == record["forward_packet_count"] + record["backward_packet_count"] == 6
    assert record["byte_count"] == record["forward_byte_count"] + record["backward_byte_count"] == 1080
    assert (record["forward_byte_count"], record["backward_byte_count"]) == (440, 640)
    assert record["payload_byte_count"] == 668                   # thống kê thêm


def test_zero_payload_packets_are_counted():
    tracker = FlowTracker(CFG)
    tracker.process(sized(tcp_event(A, 5000, B, 80, ["SYN"]), 74, 0))
    [record] = close_all(tracker)
    assert record["packet_count"] == 1 and record["payload_byte_count"] == 0


def test_flag_counts_count_flags_not_roles():
    tracker = FlowTracker(CFG)
    feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]), ("c", ["ACK"]),
         ("c", ["FIN", "ACK"]), ("s", ["RST"]))
    [record] = close_all(tracker)
    assert (record["syn_count"], record["ack_count"],
            record["fin_count"], record["rst_count"]) == (2, 3, 1, 1)   # SYN+ACK cộng cả hai


def test_udp_flag_counters_stay_zero():
    tracker = FlowTracker(CFG)
    tracker.process(udp_event(A, 40000, B, 53))
    [record] = close_all(tracker)
    assert (record["syn_count"], record["ack_count"],
            record["fin_count"], record["rst_count"]) == (0, 0, 0, 0)
    assert record["state"] == "ACTIVE" and record["midstream"] is None


def test_record_keys():
    tracker = FlowTracker(CFG)
    feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]))
    tracker.process(udp_event(A, 40000, B, 53))
    for record in close_all(tracker):
        assert list(record) == RECORD_KEYS                       # đúng tập, đúng thứ tự
        json.loads(json.dumps(record))                           # chỉ kiểu JSON
        assert "preprocess" not in record and "packet_id" not in record   # không phải event
        assert record["schema_version"] == 1


def test_record_time_fields_are_integers_and_consistent():
    tracker = FlowTracker(CFG)
    feed(tracker, ("c", ["SYN"]), ("s", ["SYN", "ACK"]), ("c", ["ACK"]))
    [record] = close_all(tracker, usec=1_790_486_523_123_456)
    assert record["duration_usec"] == 2
    assert type(record["duration_usec"]) is int
    assert record["start_time_usec"] == 1_000_000
    assert record["close_time"] == "2026-09-27T05:22:03.123456Z"
    assert record["start_time"] == "1970-01-01T00:00:01.000000Z"


def test_wire_len_missing_noted_on_flow_record():
    tracker = FlowTracker(CFG)
    event = udp_event(A, 40000, B, 53, wire_len=None)
    event["cap_len"] = 55
    tracker.process(event)
    [record] = close_all(tracker)
    assert record["byte_count"] == 55 and "wire_len_missing" in record["reasons"]


def test_malformed_noted_on_flow_record():
    tracker = FlowTracker(CFG)
    tracker.process(udp_event(A, 40000, B, 53, status="malformed"))
    tracker.process(udp_event(A, 40000, B, 53, status="malformed"))
    [record] = close_all(tracker)
    assert "malformed_packets=2" in record["reasons"]


def test_application_protocol_set_once_and_kept():
    tracker = FlowTracker(CFG)
    first = tcp_event(A, 5000, B, 80, ["SYN"])                   # chưa có app_proto
    second = tcp_event(A, 5000, B, 80, ["ACK"])
    second["preprocess"]["app_proto"] = "HTTP"
    third = tcp_event(A, 5000, B, 80, ["ACK"])
    third["preprocess"]["app_proto"] = "SMTP"                    # không được đè
    unknown = tcp_event(A, 6000, B, 80, ["ACK"])
    unknown["preprocess"]["app_proto"] = "UNKNOWN"
    for event in (first, second, third, unknown):
        tracker.process(event)
    first_flow, other_flow = close_all(tracker)
    assert first_flow["application_protocol"] == "HTTP"
    assert other_flow["application_protocol"] is None            # UNKNOWN không tính
