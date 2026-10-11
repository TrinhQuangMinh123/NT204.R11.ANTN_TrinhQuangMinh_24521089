"""Phase 3 — Flow/Connection Tracker. Event dựng tay, không qua parser (NFR-16).

T3.1: khoá hai chiều + flow_id. Các task sau thêm test vào cuối file này.
"""
from idps.core.event import new_event
from idps.core.frame import RawFrame
from idps.process.config import Config
from idps.process.flow import FlowTracker

CFG = Config.load()


def make_event(src, sport, dst, dport, proto="TCP", packet_id=1):
    """Event tối thiểu: đúng những field Flow Tracker đọc (đã qua Preprocessor)."""
    event = new_event(RawFrame(b"\x00" * 14, 1790486523, 0, 60, 1, "pcap"), packet_id)
    event["transport_proto"] = proto
    event["src_ip"], event["dst_ip"] = src, dst
    event["src_port"], event["dst_port"] = sport, dport
    event["preprocess"].update(
        transport_proto=proto, src_ip=src, dst_ip=dst, status="valid", action="forwarded"
    )
    return event


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
