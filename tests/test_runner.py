"""T3.4 — Runner và Stats: đánh số, phát cho mọi sink, đóng sink, đếm.

Nguồn giả và sink giả CHỈ nằm trong tests/ (NFR-9): thêm một module phía sau
không được kéo theo thay đổi nào trong idps/capture/ hay idps/decode/.
"""
import struct

import pytest

from idps.core.frame import RawFrame
from idps.core.runner import Runner
from idps.core.sink import EventSink
from idps.core.stats import Stats
from idps.decode.pipeline import process_frame

DST = bytes.fromhex("02420a14000a")
SRC = bytes.fromhex("02420a0a000a")

# Packet Ethernet/IPv4/TCP hợp lệ — xem ghi chú cùng nội dung ở tests/test_cli.py.
_TCP_SYN = struct.pack("!HHIIBBHHH", 54321, 80, 0x11223344, 0, 5 << 4, 0x02,
                       64240, 0, 0)
_IPV4 = struct.pack("!BBHHHBBH4s4s", (4 << 4) | 5, 0, 20 + len(_TCP_SYN),
                    0x1234, 0x4000, 64, 6, 0,
                    bytes((10, 10, 0, 10)), bytes((10, 20, 0, 10)))


def frame(data=b"", linktype=1):
    return RawFrame(
        data=data,
        ts_sec=1790486523,
        ts_usec=0,
        wire_len=len(data),
        linktype=linktype,
        source="pcap",
    )


class FakeSource:
    """Phát ra các frame cho sẵn, rồi (tuỳ chọn) ném một ngoại lệ."""

    def __init__(self, frames, raises=None):
        self._frames = frames
        self._raises = raises

    def frames(self):
        for f in self._frames:
            yield f
        if self._raises is not None:
            raise self._raises


class FakeSink(EventSink):
    """Module phía sau giả: ghi lại đã nhận gì và đã được đóng chưa."""

    def __init__(self, name="sink"):
        self.name = name
        self.events = []
        self.closed = 0

    def handle(self, event):
        self.events.append(event)

    def close(self):
        self.closed += 1


def fake_decode(status_by_id=None):
    """Thay process_frame: cho phép đặt sẵn status để kiểm Stats."""
    status_by_id = status_by_id or {}

    def decode(frame, packet_id):
        return {"packet_id": packet_id, "status": status_by_id.get(packet_id, "ok")}

    return decode


# --- Stats ------------------------------------------------------------------

def test_stats_starts_at_zero():
    s = Stats()
    assert (s.processed, s.unknown, s.malformed) == (0, 0, 0)


def test_stats_counts_each_status_once():
    s = Stats()
    for status in ["ok", "unknown", "malformed", "malformed", "ok"]:
        s.add({"status": status})
    assert (s.processed, s.unknown, s.malformed) == (5, 1, 2)


def test_stats_line_format():
    s = Stats()
    s.add({"status": "ok"})
    s.add({"status": "unknown"})
    assert s.line() == "processed=2 unknown=1 malformed=0"


# --- đánh số và phát event (REQ-12.3, 20.1) ---------------------------------

def test_packet_ids_start_at_one():
    sink = FakeSink()
    Runner(FakeSource([frame(b"a"), frame(b"b"), frame(b"c")]), [sink], fake_decode()).run()
    assert [e["packet_id"] for e in sink.events] == [1, 2, 3]


def test_extra_sink():
    """NFR-9: gắn thêm module phía sau -> nhận đúng cùng chuỗi event."""
    writer, extra = FakeSink("writer"), FakeSink("extra")
    Runner(FakeSource([frame(b"a")] * 4), [writer, extra], fake_decode()).run()
    assert [e["packet_id"] for e in writer.events] == [1, 2, 3, 4]
    assert writer.events == extra.events
    # Cùng một object event đi tới mọi sink, không nhân bản -> không có đường
    # để hai module nhìn thấy hai bản dữ liệu khác nhau.
    assert all(a is b for a, b in zip(writer.events, extra.events))


def test_empty_source_still_closes_sinks():
    sink = FakeSink()
    stats = Runner(FakeSource([]), [sink], fake_decode()).run()
    assert sink.events == [] and sink.closed == 1
    assert stats.line() == "processed=0 unknown=0 malformed=0"


def test_run_returns_the_same_stats_object():
    runner = Runner(FakeSource([frame(b"a")]), [], fake_decode())
    assert runner.run() is runner.stats


def test_sink_list_is_copied():
    sinks = [FakeSink()]
    runner = Runner(FakeSource([frame(b"a")]), sinks, fake_decode())
    sinks.append(FakeSink("them sau"))      # thêm sau khi đã dựng Runner
    runner.run()
    assert sinks[1].events == []


# --- đếm đúng theo status ----------------------------------------------------

def test_stats_from_a_run():
    decode = fake_decode({2: "unknown", 3: "malformed", 5: "malformed"})
    stats = Runner(FakeSource([frame(b"x")] * 5), [], decode).run()
    assert stats.line() == "processed=5 unknown=1 malformed=2"


# --- đóng sink trong mọi đường thoát (REQ-20.3, 1.6) ------------------------

def test_close_is_called_when_the_source_raises_keyboardinterrupt():
    sink = FakeSink()
    runner = Runner(FakeSource([frame(b"a")] * 2, raises=KeyboardInterrupt()), [sink], fake_decode())
    with pytest.raises(KeyboardInterrupt):
        runner.run()
    assert sink.closed == 1                       # đã đóng trước khi ném tiếp
    assert len(sink.events) == 2                  # giữ phần đã ghi
    assert runner.stats.processed == 2            # main.py vẫn in được thống kê


def test_close_is_called_when_the_source_fails():
    sink = FakeSink()
    runner = Runner(FakeSource([frame(b"a")], raises=OSError("doc file loi")), [sink], fake_decode())
    with pytest.raises(OSError):
        runner.run()
    assert sink.closed == 1


def test_every_sink_is_closed_exactly_once():
    a, b = FakeSink("a"), FakeSink("b")
    Runner(FakeSource([frame(b"x")]), [a, b], fake_decode()).run()
    assert (a.closed, b.closed) == (1, 1)


# --- nối với pipeline thật ---------------------------------------------------

def test_runner_with_the_real_pipeline():
    """decode được tiêm vào: main.py nối process_frame vào đúng chỗ này."""
    good = frame(DST + SRC + b"\x08\x00" + _IPV4 + _TCP_SYN)
    arp = frame(DST + SRC + b"\x08\x06" + b"arp")
    short = frame(b"\x00" * 3)
    sink = FakeSink()
    stats = Runner(FakeSource([good, arp, short]), [sink], process_frame).run()

    assert [e["status"] for e in sink.events] == ["ok", "unknown", "malformed"]
    assert stats.line() == "processed=3 unknown=1 malformed=1"
