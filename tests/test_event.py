"""T2.3 — khung event: tập khoá, thứ tự, timestamp, base64, status."""
import json

import pytest

from idps.core.event import (
    SCHEMA_VERSION,
    add_error,
    b64,
    compute_status,
    format_timestamp,
    new_event,
)
from idps.core.frame import RawFrame


def make_frame(**kw):
    base = dict(
        data=b"\x00" * 14,
        ts_sec=1790486523,
        ts_usec=123456,
        wire_len=60,
        linktype=1,
        source="pcap",
    )
    base.update(kw)
    return RawFrame(**base)


# --- tập khoá và thứ tự (I-2) ----------------------------------------------

def test_same_keys(event_keys):
    """Mọi event có cùng tập khoá cấp cao, đúng thứ tự §5.4."""
    a = new_event(make_frame(), 1)
    b = new_event(make_frame(data=b"", linktype=113, source="live"), 2)
    assert tuple(a) == event_keys
    assert tuple(b) == event_keys


def test_frame_values_copied():
    e = new_event(make_frame(data=b"abcd", wire_len=60, source="live"), 7)
    assert e["packet_id"] == 7
    assert e["cap_len"] == 4          # số byte thực có
    assert e["wire_len"] == 60        # độ dài gốc trên dây
    assert e["source"] == "live"
    assert e["linktype"] == 1


def test_skeleton_starts_empty():
    e = new_event(make_frame(), 1)
    assert e["errors"] == []
    assert e["status"] == "ok"
    for key in ("link_proto", "src_ip", "tcp", "app", "detect_method"):
        assert e[key] is None


def test_schema_version():
    assert SCHEMA_VERSION == 2
    assert new_event(make_frame(), 1)["schema_version"] == 2


# --- schema v2: ba khoá mới của bài 2 (I-12, NFR-17, §5.2) ------------------

EMPTY_DECODED = {"value": None, "rule": None, "status": "not_applicable", "reasons": []}


def test_schema_v2_keys():
    """Ba khoá cấp cao của bài 2 có mặt, đúng thứ tự, với khung con đầy đủ.

    Dựng rỗng ngay trong new_event() (không do từng stage tự thêm) là bất biến
    I-12: một event bị chặn giữa chuỗi stage vẫn đủ ba khoá này. Năm mục của
    `decode` là DecodedValue rỗng — bốn khoá luôn có mặt (NFR-17, §5.1).
    """
    e = new_event(make_frame(), 1)
    assert tuple(e)[-3:] == ("decode", "preprocess", "flow")

    assert tuple(e["decode"]) == (
        "status", "reasons", "uri", "query", "body_form", "body_text", "mime",
    )
    assert e["decode"]["status"] == "not_applicable"
    assert e["decode"]["reasons"] == []
    for field in ("uri", "query", "body_form", "body_text", "mime"):
        assert e["decode"][field] == EMPTY_DECODED

    assert tuple(e["preprocess"]) == (
        "status", "action", "reasons", "transport_proto", "app_proto",
        "src_ip", "dst_ip", "dns_names", "http_host", "http_header_names",
        "path", "query_string", "ts_usec",
    )
    assert e["preprocess"]["status"] is None
    assert e["preprocess"]["action"] is None
    assert e["preprocess"]["reasons"] == []
    assert e["preprocess"]["dns_names"] == []
    assert e["preprocess"]["http_header_names"] == []

    assert tuple(e["flow"]) == ("flow_id", "direction", "state", "reasons")
    assert e["flow"]["flow_id"] is None
    assert e["flow"]["state"] is None
    assert e["flow"]["reasons"] == []


def test_v2_keys_are_not_shared_between_events():
    """Mỗi event có list `reasons` RIÊNG — không alias giữa hai event (I-1)."""
    a = new_event(make_frame(), 1)
    b = new_event(make_frame(), 2)
    a["decode"]["uri"]["reasons"].append("x")
    a["preprocess"]["reasons"].append("y")
    a["flow"]["reasons"].append("z")
    assert b["decode"]["uri"]["reasons"] == []
    assert b["preprocess"]["reasons"] == []
    assert b["flow"]["reasons"] == []


# --- JSON (I-3) -------------------------------------------------------------

def test_json_safe():
    """Dữ liệu packet chứa \\n không thể làm event vỡ thành hai dòng."""
    e = new_event(make_frame(), 1)
    e["app"] = {"uri": 'GET /\r\n{"packet_id":999}\n', "raw": b64(b"\xff\xfe")}
    add_error(e, "http", "lý do có\nxuống dòng")
    line = json.dumps(e, ensure_ascii=True, separators=(",", ":"))
    assert "\n" not in line and "\r" not in line
    assert json.loads(line)["app"]["uri"] == 'GET /\r\n{"packet_id":999}\n'


def test_json_needs_no_custom_encoder():
    json.dumps(new_event(make_frame(), 1))


# --- timestamp (ADR-7) ------------------------------------------------------

def test_timestamp_epoch():
    assert format_timestamp(0, 5) == "1970-01-01T00:00:00.000005Z"


@pytest.mark.parametrize(
    "ts_sec, ts_usec, expected",
    [
        (0, 0, "1970-01-01T00:00:00.000000Z"),
        (1790486523, 123456, "2026-09-27T05:22:03.123456Z"),
        (1790486523, 1, "2026-09-27T05:22:03.000001Z"),   # không mất micro giây
        (1, 1_000_000, "1970-01-01T00:00:02.000000Z"),    # usec tràn -> dồn sang giây
        (0, 4_000_000, "1970-01-01T00:00:04.000000Z"),    # uint32 rác trong PCAP
    ],
)
def test_timestamp_values(ts_sec, ts_usec, expected):
    assert format_timestamp(ts_sec, ts_usec) == expected


def test_timestamp_length_is_fixed():
    """Độ dài cố định -> so sánh chuỗi bằng < ra đúng thứ tự thời gian."""
    early = format_timestamp(1790486523, 999999)
    late = format_timestamp(1790486524, 0)
    assert len(early) == len(late) == 27
    assert early < late


# --- base64 (REQ-12.5, I-4) -------------------------------------------------

def test_b64_empty():
    assert b64(b"") == ""


@pytest.mark.parametrize("raw", [b"\x00", b"GET / HTTP/1.1\r\n", bytes(range(256))])
def test_b64_roundtrip(raw):
    import base64 as _b64
    assert _b64.b64decode(b64(raw)) == raw


def test_b64_is_ascii_string():
    value = b64(b"\xff\xfe\xfd")
    assert isinstance(value, str)
    value.encode("ascii")  # không ném -> nhét vào JSON được


# --- status (§5.4) ----------------------------------------------------------

def test_status_ok():
    assert compute_status(new_event(make_frame(), 1)) == "ok"


@pytest.mark.parametrize("key", ["link_proto", "network_proto", "transport_proto"])
def test_status_unknown_per_layer(key):
    e = new_event(make_frame(), 1)
    e[key] = "UNKNOWN"
    assert compute_status(e) == "unknown"


def test_app_unknown_is_still_ok():
    """app_proto UNKNOWN không làm status thành unknown (§5.4)."""
    e = new_event(make_frame(), 1)
    e["app_proto"] = "UNKNOWN"
    assert compute_status(e) == "ok"


def test_status_malformed_beats_unknown():
    e = new_event(make_frame(), 1)
    e["transport_proto"] = "UNKNOWN"
    add_error(e, "ipv4", "total_length 400 > 60 byte có thật")
    assert compute_status(e) == "malformed"


def test_add_error_records_layer_and_reason():
    e = new_event(make_frame(), 1)
    add_error(e, "capture", "truncated record")
    add_error(e, "link", "ethernet header needs 14 bytes")
    assert e["errors"] == [
        {"layer": "capture", "reason": "truncated record"},
        {"layer": "link", "reason": "ethernet header needs 14 bytes"},
    ]
