"""T2.5 — process_frame(): tầng liên kết + lưới an toàn (I-1, REQ-14.1, 15.2)."""
import json
import random

import pytest

from idps.core.frame import RawFrame
from idps.decode import pipeline
from idps.decode.pipeline import process_frame

DST = bytes.fromhex("02420a14000a")
SRC = bytes.fromhex("02420a0a000a")
LINKTYPE_LINUX_SLL = 113


def eth(ethertype=0x0800, payload=b""):
    return DST + SRC + ethertype.to_bytes(2, "big") + payload


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
    """Tầng network đã nhận diện là IPv4; khoá ipv4 do T5.4 điền."""
    event = process_frame(frame(eth(0x0800, b"\x45\x00")), 1)
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
    event = process_frame(frame(eth(0x0800, b"\x45"), truncated=True), 1)
    assert event["errors"] == [{"layer": "capture", "reason": "truncated record"}]
    assert event["ethernet"] is not None     # vẫn parse phần đọc được
    assert event["network_proto"] == "IPv4"
    assert event["status"] == "malformed"


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
