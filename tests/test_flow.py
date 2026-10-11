"""Phase 3–4 — Flow/Connection Tracker. Event dựng tay, không qua parser (NFR-16).

T3.x: flow, trạng thái, thống kê, hết hạn. T4.x (cuối file): gom thư SMTP.
"""
import base64
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


# --- T3.5 hết hạn theo trạng thái, bảng đầy, lý do đóng -----------------------

SEC = 1_000_000
# Năm ngưỡng KHÁC NHAU để ca nào tra nhầm ngưỡng thì test fail.
LIMITS = Config.load(None, [("tcp.new", "10"), ("tcp.established", "100"),
                            ("tcp.closed", "20"), ("udp.new", "5"),
                            ("udp.established", "50")])


class RecordingSink:
    """Sink giả: giữ record, và gọi `on_handle` để test soi trạng thái lúc nhận."""

    def __init__(self, on_handle=None):
        self.records, self.closed, self.on_handle = [], False, on_handle

    def handle(self, record):
        if self.on_handle:
            self.on_handle(record)
        self.records.append(record)

    def close(self):
        self.closed = True


def other_flow(ts):
    """Packet của một flow KHÁC, chỉ để đẩy đồng hồ tới `ts`."""
    return udp_event("10.99.0.1", 1, "10.99.0.2", 2, ts=ts)


def reasons_closed(sink, flow_id):
    return [r["close_reason"] for r in sink.records if r["flow_id"] == flow_id]


def at_ts(event, ts):
    event["preprocess"]["ts_usec"] = ts
    return event


CASES = {   # tên: (các packet dựng flow 1 ở ts=0, ngưỡng giây, close_reason)
    "tcp_handshake": ([("c", ["SYN"])], 10, "idle_new"),
    "tcp_established": ([("c", ["ACK"])], 100, "idle_established"),
    "tcp_closing": ([("c", ["ACK"]), ("c", ["FIN", "ACK"])], 100, "idle_established"),
    "tcp_closed": ([("c", ["ACK"]), ("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"]),
                    ("c", ["ACK"])], 20, "idle_closed"),
    "tcp_reset": ([("c", ["ACK"]), ("s", ["RST"])], 20, "idle_closed"),
}


def test_expire_per_state():
    for name, (packets, limit, expected) in CASES.items():
        sink = RecordingSink()
        tracker = FlowTracker(LIMITS, [sink])
        for side, flags in packets:
            src = (A, 5000, B, 80) if side == "c" else (B, 80, A, 5000)
            tracker.process(tcp_event(*src, flags, ts=0))
        tracker.process(other_flow(limit * SEC))          # đúng ngưỡng: CHƯA hết hạn
        assert sink.records == [], name
        tracker.process(other_flow(limit * SEC + 1))      # quá ngưỡng 1 µs
        assert reasons_closed(sink, 1) == [expected], name


def test_expire_udp_by_direction_seen():
    sink = RecordingSink()
    tracker = FlowTracker(LIMITS, [sink])
    tracker.process(udp_event(A, 40000, B, 53, ts=0))                 # flow 1: một chiều
    tracker.process(udp_event(A, 41000, B, 53, ts=0))                 # flow 2: …
    tracker.process(udp_event(B, 53, A, 41000, ts=0))                 # … đã có chiều ngược
    tracker.process(other_flow(5 * SEC + 1))                          # quá udp.new (5)
    assert reasons_closed(sink, 1) == ["idle_new"]
    assert reasons_closed(sink, 2) == []                              # ngưỡng 50, chưa tới
    tracker.process(other_flow(50 * SEC + 1))
    assert reasons_closed(sink, 2) == ["idle_established"]


def test_closed_lingers():
    sink = RecordingSink()
    tracker = FlowTracker(LIMITS, [sink])
    for side, flags in (("c", ["ACK"]), ("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"]),
                        ("c", ["ACK"])):
        src = (A, 5000, B, 80) if side == "c" else (B, 80, A, 5000)
        tracker.process(tcp_event(*src, flags, ts=0))
    retransmit = at_ts(tcp_event(B, 80, A, 5000, ["FIN", "ACK"]), 15 * SEC)  # < tcp.closed
    tracker.process(retransmit)
    assert retransmit["flow"]["flow_id"] == 1                         # không đẻ flow mới
    assert retransmit["flow"]["state"] == "CLOSED"
    assert sink.records == []                                         # còn trong bảng
    assert tracker.table.flows()[0].packet_count == 5                 # packet muộn được đếm
    tracker.process(other_flow(15 * SEC + 20 * SEC + 1))              # last_seen mới = 15s
    assert reasons_closed(sink, 1) == ["idle_closed"]


def test_clock_from_packet():
    sink = RecordingSink()
    tracker = FlowTracker(LIMITS, [sink])
    tracker.process(tcp_event(A, 5000, B, 80, ["SYN"], ts=0))
    tracker.process(other_flow(2 * 3600 * SEC))        # đẩy timestamp lên 2 giờ, không chờ thật
    assert reasons_closed(sink, 1) == ["idle_new"]
    assert sink.records[0]["close_time"] == "1970-01-01T02:00:00.000000Z"


def test_clock_never_goes_backwards():
    tracker = FlowTracker(LIMITS, [RecordingSink()])
    tracker.process(other_flow(100 * SEC))
    tracker.process(other_flow(10 * SEC))               # timestamp lùi
    assert tracker.clock_usec == 100 * SEC
    flow = tracker.table.flows()[0]
    assert flow.last_seen_usec == 100 * SEC and flow.last_seen_usec >= flow.start_usec


def test_expire_before_assign():
    sink = RecordingSink()
    tracker = FlowTracker(LIMITS, [sink])
    first = tcp_event(A, 5000, B, 80, ["SYN"], ts=0)
    again = tcp_event(A, 5000, B, 80, ["SYN"], ts=11 * SEC)    # quá tcp.new (10)
    tracker.process(first)
    tracker.process(again)
    assert first["flow"]["flow_id"] == 1
    assert again["flow"]["flow_id"] == 2                      # flow MỚI, không hồi sinh flow cũ
    assert reasons_closed(sink, 1) == ["idle_new"]
    assert again["flow"]["direction"] == "forward"


def test_table_full():
    sink = RecordingSink()
    cfg = Config.load(None, [("max_active_flows", "3")])
    tracker = FlowTracker(cfg, [sink])
    for n in range(10):
        tracker.process(tcp_event(A, 5000 + n, B, 80, ["SYN"], ts=n))
        assert len(tracker.table) <= 3                        # I-17: mọi thời điểm
    assert [r["close_reason"] for r in sink.records] == ["table_full"] * 7
    assert [r["flow_id"] for r in sink.records] == [1, 2, 3, 4, 5, 6, 7]   # cũ nhất trước


def test_table_full_existing_flow_does_not_evict():
    sink = RecordingSink()
    tracker = FlowTracker(Config.load(None, [("max_active_flows", "2")]), [sink])
    for n in range(2):
        tracker.process(tcp_event(A, 5000 + n, B, 80, ["SYN"], ts=n))
    tracker.process(tcp_event(A, 5000, B, 80, ["ACK"], ts=5))   # flow đã có -> không cần chỗ
    assert sink.records == [] and len(tracker.table) == 2


def test_evict_picks_oldest_last_seen_not_oldest_created():
    sink = RecordingSink()
    tracker = FlowTracker(Config.load(None, [("max_active_flows", "2")]), [sink])
    tracker.process(tcp_event(A, 5000, B, 80, ["SYN"], ts=0))   # flow 1
    tracker.process(tcp_event(A, 5001, B, 80, ["SYN"], ts=1))   # flow 2
    tracker.process(tcp_event(A, 5000, B, 80, ["ACK"], ts=2))   # flow 1 vừa hoạt động
    tracker.process(tcp_event(A, 5002, B, 80, ["SYN"], ts=3))   # cần chỗ
    assert [r["flow_id"] for r in sink.records] == [2]


def test_record_before_removal():
    seen_in_table = []

    def check(record):
        seen_in_table.append(record["flow_id"] in [f.flow_id for f in tracker.table.flows()])

    sink = RecordingSink(on_handle=check)
    tracker = FlowTracker(LIMITS, [sink])
    tracker.process(tcp_event(A, 5000, B, 80, ["SYN"], ts=0))
    tracker.process(other_flow(11 * SEC))                      # hết hạn
    tracker.close()                                            # end_of_run
    assert seen_in_table == [True, True]                       # record tới sink khi flow CÒN trong bảng
    assert len(tracker.table) == 0


def test_every_flow_closed_once():
    sink = RecordingSink()
    tracker = FlowTracker(Config.load(None, [("max_active_flows", "4"), ("tcp.new", "10")]),
                          [sink])
    for n in range(12):                                        # đủ cả table_full, hết hạn
        tracker.process(tcp_event(A, 5000 + n, B, 80, ["SYN"], ts=n * 3 * SEC))
    tracker.close()
    created = tracker._next_flow_id - 1
    ids = [r["flow_id"] for r in sink.records]
    assert created == 12 and len(ids) == 12 and len(set(ids)) == 12
    assert {r["close_reason"] for r in sink.records} >= {"idle_new", "end_of_run"}


def test_close_flushes_before_closing_sinks():
    log = []

    class Sink(RecordingSink):
        def handle(self, record):
            log.append("record")

        def close(self):
            log.append("close")

    tracker = FlowTracker(LIMITS, [Sink()])
    tracker.process(tcp_event(A, 5000, B, 80, ["SYN"], ts=0))
    tracker.process(tcp_event(A, 5001, B, 80, ["SYN"], ts=1))
    tracker.close()
    assert log == ["record", "record", "close"]


def test_end_of_run_flushes_in_creation_order():
    sink = RecordingSink()
    tracker = FlowTracker(LIMITS, [sink])
    for n in range(3):
        tracker.process(tcp_event(A, 5000 + n, B, 80, ["SYN"], ts=0))
    tracker.close()
    assert [r["flow_id"] for r in sink.records] == [1, 2, 3]
    assert {r["close_reason"] for r in sink.records} == {"end_of_run"}


def test_extra_flow_sink():
    # REQ-35.4: MỌI sink đã đăng ký đều nhận record, không riêng bộ ghi tệp.
    first, extra = RecordingSink(), RecordingSink()
    tracker = FlowTracker(LIMITS, [first, extra])
    tracker.process(tcp_event(A, 5000, B, 80, ["SYN"], ts=0))
    tracker.close()
    assert len(first.records) == len(extra.records) == 1
    assert first.records[0] == extra.records[0]
    assert first.closed and extra.closed


def test_stage_error_counts_per_stage():
    # Đếm ngoại lệ bất ngờ theo tên stage — nguồn của decode_errors/flow_errors.
    from idps.process.chain import ProcessingChain, Stage

    class Boom(Stage):
        name = "flow"

        def process(self, event):
            raise RuntimeError("bug")

    chain = ProcessingChain([Boom()])
    chain.handle(make_event(A, 5000, B, 80))
    chain.handle(make_event(A, 5000, B, 80))
    assert chain.error_counts == {"flow": 2}


# --- T4.2: gom thư SMTP ở mức flow (REQ-40, ADR-26) --------------------------

SMTP_MAIL = (b"Subject: hi\r\nContent-Transfer-Encoding: base64\r\n\r\n"
             b"SGVsbG8gd29ybGQ=\r\n")


def smtp_packet(side, payload=b"", app=None, ts=1_000_000, port=5000):
    """Packet SMTP dựng tay: c = client A:5000 → server B:25, s = chiều ngược lại.

    `app` là khoá `app` mà parser bài 1 sẽ điền (lệnh/reply); packet nội dung thư
    không có `app` — parser không parse nội dung thư.
    """
    if side == "c":
        event = tcp_event(A, port, B, 25, ["ACK", "PSH"], payload_len=len(payload), ts=ts)
    else:
        event = tcp_event(B, 25, A, port, ["ACK", "PSH"], payload_len=len(payload), ts=ts)
    event["tcp"]["payload_b64"] = base64.b64encode(payload).decode("ascii")
    event["preprocess"]["app_proto"] = "SMTP" if app else None
    event["app"] = app
    return event


def command(name):
    return {"kind": "command", "command": name, "status_code": None}


def reply(code):
    return {"kind": "response", "command": None, "status_code": code}


def run_flow(packets, cfg=CFG):
    """Đưa packet vào tracker, đóng, trả (record duy nhất, tracker)."""
    sink = RecordingSink()
    tracker = FlowTracker(cfg, [sink])
    for n, packet in enumerate(packets):
        packet["preprocess"]["ts_usec"] = 1_000_000 + n
        tracker.process(packet)
    tracker.close()
    assert len(sink.records) == 1
    return sink.records[0], tracker


def data_session(*body, accepted=True):
    """DATA → 354 → các packet nội dung (mỗi phần tử của `body` là một packet)."""
    packets = [smtp_packet("c", b"DATA\r\n", command("DATA")),
               smtp_packet("s", b"354 go ahead\r\n", reply(354 if accepted else 503))]
    return packets + [smtp_packet("c", chunk) for chunk in body]


def test_mail_over_three_packets():
    data = SMTP_MAIL + b"\r\n.\r\n"
    record, _ = run_flow(data_session(data[:20], data[20:50], data[50:]))
    assert len(record["mails"]) == 1
    mail = record["mails"][0]
    assert mail["rule"] == "F8" and mail["status"] == "ok"
    assert mail["value"]["parts"][0]["text"] == "Hello world"
    assert record["packet_count"] == 5 and record["reasons"] == []


def test_two_mails_one_connection():
    data = SMTP_MAIL + b"\r\n.\r\n"
    packets = (data_session(data) + [smtp_packet("s", b"250 ok\r\n", reply(250))]
               + data_session(data))
    record, _ = run_flow(packets)
    assert len(record["mails"]) == 2


def test_no_354_means_no_mail():
    # R14: PCAP thiếu packet chứa 354 → không gom, nhưng flow vẫn chốt thống kê đúng.
    packets = [smtp_packet("c", b"DATA\r\n", command("DATA")),
               smtp_packet("c", SMTP_MAIL + b"\r\n.\r\n")]
    record, _ = run_flow(packets)
    assert record["mails"] == []
    assert record["packet_count"] == 2 and record["payload_byte_count"] > 0


def test_refused_data_means_no_mail():
    record, _ = run_flow(data_session(SMTP_MAIL + b"\r\n.\r\n", accepted=False))
    assert record["mails"] == []


def test_354_from_wrong_direction_is_ignored():
    packets = [smtp_packet("c", b"DATA\r\n", command("DATA")),
               smtp_packet("c", b"354 x\r\n", reply(354)),          # cùng chiều với DATA
               smtp_packet("c", SMTP_MAIL + b"\r\n.\r\n")]
    record, _ = run_flow(packets)
    assert record["mails"] == []


def test_flow_closed_with_data_in_buffer():
    record, _ = run_flow(data_session(SMTP_MAIL))               # không có dấu kết thúc
    assert len(record["mails"]) == 1
    mail = record["mails"][0]
    assert mail["status"] == "partial" and "no_end_of_data_marker" in mail["reasons"]
    assert mail["value"]["parts"][0]["text"] == "Hello world"


def test_non_smtp_flow_has_no_mails():
    packets = [tcp_event(A, 5000, B, 80, ["SYN"]), tcp_event(B, 80, A, 5000, ["SYN", "ACK"])]
    record, _ = run_flow(packets)
    assert record["mails"] == []


def test_reassembly_limit_keeps_partial_and_stats():
    cfg = Config.load(None, [("max_reassembly_bytes", "40")])
    record, _ = run_flow(data_session(SMTP_MAIL + b"\r\n.\r\n"), cfg)
    assert "reassembly_limit=40" in record["reasons"]
    # Chỗ cắt rơi vào header nên mime_decode có thể báo nặng hơn `partial`; điều cần
    # giữ là phần đã gom VẪN được giải mã, không báo `ok`, và nêu giới hạn.
    assert len(record["mails"]) == 1
    assert record["mails"][0]["status"] != "ok"
    assert "reassembly_limit=40" in record["mails"][0]["reasons"]
    assert record["packet_count"] == 3


def test_payload_gap_marks_mail_partial():
    session = data_session(SMTP_MAIL[:30], SMTP_MAIL[30:] + b"\r\n.\r\n")
    session[-1]["errors"].append({"layer": "capture", "reason": "truncated record"})
    record, _ = run_flow(session)
    assert "payload_gap" in record["reasons"]
    assert record["mails"][0]["status"] == "partial"
    assert "payload_gap" in record["mails"][0]["reasons"]


def test_record_with_mails_is_json_safe():
    record, _ = run_flow(data_session(SMTP_MAIL + b"\r\n.\r\n"))
    assert json.loads(json.dumps(record)) == record


def test_total_budget_stops_largest_buffer_first():
    # I-19, REQ-40.5: tổng mọi bộ đệm ≤ ngưỡng sau MỖI packet; flow lớn nhất bị dừng trước.
    cfg = Config.load(None, [("max_reassembly_total_bytes", "100")])
    sink = RecordingSink()
    tracker = FlowTracker(cfg, [sink])
    ports = (5001, 5002, 5003)
    for port in ports:                                   # cả ba vào pha DATA, bộ đệm rỗng
        tracker.process(smtp_packet("c", b"DATA\r\n", command("DATA"), port=port))
        tracker.process(smtp_packet("s", b"354 go\r\n", reply(354), port=port))

    def held():
        return sum(f.mail_buffer.buffered for f in tracker.table.flows() if f.mail_buffer)

    for port, size in ((5001, 50), (5002, 30), (5003, 15), (5002, 10), (5003, 30)):
        tracker.process(smtp_packet("c", b"x" * size, port=port))
        assert held() <= 100
    flows = {f.endpoint_a[1]: f for f in tracker.table.flows()}
    assert flows[5001].mail_stopped                      # 50 byte: lớn nhất khi tổng chạm 105
    assert not flows[5002].mail_stopped and not flows[5003].mail_stopped
    tracker.close()
    records = {r["endpoint_a"]["port"]: r for r in sink.records}
    assert len(records) == 3                             # mọi flow vẫn được chốt
    assert "reassembly_total_limit=100" in records[5001]["reasons"]
    assert records[5001]["mails"][0]["status"] != "ok"   # phần đã gom vẫn được giải mã
    assert "reassembly_total_limit=100" in records[5001]["mails"][0]["reasons"]
    assert records[5001]["packet_count"] == 3            # DATA + 354 + 1 packet nội dung
    assert records[5002]["packet_count"] == records[5003]["packet_count"] == 4
    assert "reassembly_total_limit=100" not in records[5002]["reasons"]
