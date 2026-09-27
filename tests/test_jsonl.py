"""T3.3 — EventSink và JsonlWriter: một dòng JSON hợp lệ cho mỗi event."""
import json

import pytest

from idps.core.event import new_event
from idps.core.frame import RawFrame
from idps.core.sink import EventSink
from idps.output.jsonl import JsonlWriter


def make_event(packet_id=1, **overrides):
    frame = RawFrame(
        data=b"\x00" * 14,
        ts_sec=1790486523,
        ts_usec=123456,
        wire_len=14,
        linktype=1,
        source="pcap",
    )
    event = new_event(frame, packet_id)
    event.update(overrides)
    return event


def lines_of(path):
    return path.read_text(encoding="ascii").splitlines()


# --- giao diện EventSink ----------------------------------------------------

def test_base_sink_requires_handle():
    """Quên cài handle() thì vỡ ngay chứ không im lặng nuốt event."""
    with pytest.raises(NotImplementedError):
        EventSink().handle({})


def test_base_sink_close_is_a_no_op():
    """Sink không có tài nguyên (vd bộ đếm của bài sau) không phải cài close()."""
    assert EventSink().close() is None


def test_writer_is_an_event_sink():
    assert issubclass(JsonlWriter, EventSink)


# --- một dòng cho một event (REQ-13.1, 13.2) --------------------------------

def test_one_line_per_event(tmp_path):
    out = tmp_path / "events.jsonl"
    writer = JsonlWriter(out)
    for i in range(1, 4):
        writer.handle(make_event(i))
    writer.close()

    lines = lines_of(out)
    assert len(lines) == 3
    assert [json.loads(line)["packet_id"] for line in lines] == [1, 2, 3]


def test_every_line_is_valid_json(tmp_path):
    """NFR-3: đọc từng dòng bằng json parser, 0 dòng lỗi."""
    out = tmp_path / "events.jsonl"
    writer = JsonlWriter(out)
    writer.handle(make_event(1))
    writer.handle(make_event(2, app_proto="HTTP", errors=[{"layer": "http", "reason": "x"}]))
    writer.close()
    for line in lines_of(out):
        json.loads(line)


def test_key_order_survives_the_round_trip(tmp_path, event_keys):
    """I-2: thứ tự khoá trong file đúng như design §5.4."""
    out = tmp_path / "events.jsonl"
    writer = JsonlWriter(out)
    writer.handle(make_event(1))
    writer.close()
    assert tuple(json.loads(lines_of(out)[0])) == event_keys


def test_compact_separators(tmp_path):
    """Không khoảng trắng thừa -> file tất định và nhỏ (NFR-2)."""
    out = tmp_path / "events.jsonl"
    writer = JsonlWriter(out)
    writer.handle(make_event(1))
    writer.close()
    assert lines_of(out)[0].startswith('{"schema_version":1,"packet_id":1,')


# --- chống vỡ dòng (I-3) -----------------------------------------------------

def test_newline_in_packet_data_cannot_split_a_line(tmp_path):
    """Kẻ tấn công nhét "\\n{...}" vào URI vẫn chỉ tạo ra MỘT dòng."""
    payload = 'GET /\n{"packet_id":999,"status":"ok"}\r\n'
    out = tmp_path / "events.jsonl"
    writer = JsonlWriter(out)
    writer.handle(make_event(1, app={"uri": payload}))
    writer.close()

    lines = lines_of(out)
    assert len(lines) == 1
    assert json.loads(lines[0])["app"]["uri"] == payload
    assert json.loads(lines[0])["packet_id"] == 1


def test_non_ascii_is_escaped(tmp_path):
    """ensure_ascii=True: file chỉ chứa byte ASCII, đọc lại vẫn ra chuỗi gốc."""
    out = tmp_path / "events.jsonl"
    writer = JsonlWriter(out)
    writer.handle(make_event(1, app={"uri": "/tìm?q=á"}))
    writer.close()

    raw = out.read_bytes()
    assert all(b < 128 for b in raw)
    assert json.loads(lines_of(out)[0])["app"]["uri"] == "/tìm?q=á"


# --- ghi ngay, không đợi close (REQ-1.3, ADR-8) -----------------------------

def test_flush_makes_the_line_readable_before_close(tmp_path):
    out = tmp_path / "events.jsonl"
    writer = JsonlWriter(out)
    writer.handle(make_event(1))
    assert len(lines_of(out)) == 1      # đọc được TRONG LÚC writer còn mở
    writer.handle(make_event(2))
    assert len(lines_of(out)) == 2
    writer.close()


def test_close_twice_is_harmless(tmp_path):
    """Runner gọi close() trong finally, có đường vừa hết file vừa bị Ctrl+C."""
    writer = JsonlWriter(tmp_path / "events.jsonl")
    writer.close()
    writer.close()


def test_file_is_closed_after_close(tmp_path):
    writer = JsonlWriter(tmp_path / "events.jsonl")
    writer.close()
    with pytest.raises(ValueError):
        writer.handle(make_event(1))


# --- lỗi mở file (REQ-13.4, 20.4) -------------------------------------------

def test_opening_a_directory_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        JsonlWriter(tmp_path)


def test_missing_parent_directory_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        JsonlWriter(tmp_path / "khong-co" / "events.jsonl")


def test_error_happens_at_construction_not_later(tmp_path):
    """Lỗi phải lộ ra lúc dựng sink, vì main.py dựng sink TRƯỚC nguồn."""
    out = tmp_path / "events.jsonl"
    out.write_text("da ton tai")
    writer = JsonlWriter(out)           # "w" -> ghi đè, không lỗi
    writer.close()
    assert out.read_text() == ""
