"""T2.2 — hợp đồng lõi: RawFrame bất biến, ParseResult, need()."""
import dataclasses
import json

import pytest

from idps.core.frame import RawFrame
from idps.decode.common import ParseResult, need


def make_frame(**kw):
    base = dict(
        data=b"\x00" * 14,
        ts_sec=1790486523,
        ts_usec=123456,
        wire_len=14,
        linktype=1,
        source="pcap",
    )
    base.update(kw)
    return RawFrame(**base)


# --- RawFrame ---------------------------------------------------------------

def test_frame_keeps_values():
    f = make_frame(data=b"abc", wire_len=3)
    assert f.data == b"abc"
    assert (f.ts_sec, f.ts_usec) == (1790486523, 123456)
    assert f.linktype == 1 and f.source == "pcap"


def test_truncated_defaults_to_false():
    assert make_frame().truncated is False


def test_frame_is_frozen():
    """Không tầng nào sửa được frame gốc đã bắt được."""
    f = make_frame()
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.data = b"khac"
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.ts_sec = 0


def test_frame_has_no_extra_attributes():
    """slots=True: không gắn thêm được trường ngoài hợp đồng §5.1."""
    with pytest.raises(AttributeError):
        make_frame().note = "x"


def test_frame_fields_are_json_types():
    """Không có object thư viện capture nào lọt sang tầng decode (C-6)."""
    d = dataclasses.asdict(make_frame())
    d["data"] = d["data"].hex()  # bytes không phải kiểu JSON, phần còn lại phải là
    json.dumps(d)


# --- ParseResult ------------------------------------------------------------

def test_parse_result_defaults():
    r = ParseResult()
    assert r.fields == {} and r.payload == b""
    assert r.next_proto is None and r.error is None


def test_parse_result_fields_not_shared():
    """default_factory: mỗi kết quả có dict riêng, không dùng chung một dict."""
    a, b = ParseResult(), ParseResult()
    a.fields["x"] = 1
    assert b.fields == {}


def test_parse_result_allows_fields_with_error():
    """REQ-8.5: giữ phần đã parse được kèm lý do lỗi."""
    r = ParseResult(fields={"ancount": 5}, error="answer count mismatch")
    assert r.fields == {"ancount": 5} and r.error == "answer count mismatch"


# --- need() -----------------------------------------------------------------

def test_need_exact_fit():
    assert need(b"abc", 0, 3) is True


def test_need_past_end():
    assert need(b"abc", 1, 3) is False


@pytest.mark.parametrize(
    "offset, n, expected",
    [
        (0, 0, True),    # không cần byte nào
        (3, 0, True),    # ngay sau byte cuối, đọc 0 byte vẫn hợp lệ
        (4, 0, False),   # offset đã ra ngoài buffer
        (2, 1, True),    # byte cuối cùng
        (2, 2, False),
        (-1, 1, False),  # offset âm: slice của Python sẽ đếm ngược từ cuối
        (0, -1, False),
    ],
)
def test_need_boundaries(offset, n, expected):
    assert need(b"abc", offset, n) is expected


def test_need_on_empty_data():
    assert need(b"", 0, 1) is False
    assert need(b"", 0, 0) is True
