"""T3.2 — PcapSource: magic, thứ tự, timestamp, bản ghi cụt (REQ-2, 17.4).

File PCAP mẫu dựng bằng struct ngay trong test, không commit file nhị phân:
test đọc được cả ý nghĩa từng byte, và đổi một ca lỗi chỉ là đổi một tham số.
"""
import struct

import pytest

from idps.capture import SourceError
from idps.capture.pcap import PcapSource

MAGIC_USEC_LE = b"\xd4\xc3\xb2\xa1"
MAGIC_USEC_BE = b"\xa1\xb2\xc3\xd4"
MAGIC_NANO_LE = b"\x4d\x3c\xb2\xa1"
MAGIC_NANO_BE = b"\xa1\xb2\x3c\x4d"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"

_BIG_ENDIAN_MAGICS = (MAGIC_USEC_BE, MAGIC_NANO_BE)

FRAME = bytes.fromhex("0242" "0a14000a" "0242" "0a0a000a" "0800") + b"\x45\x00payload"


def _endian(magic):
    return ">" if magic in _BIG_ENDIAN_MAGICS else "<"


def record(data, ts_sec=0, ts_frac=0, incl_len=None, orig_len=None, magic=MAGIC_USEC_LE):
    """Một bản ghi: header 16 byte (ts_sec, ts_frac, incl_len, orig_len) + data.

    incl_len khai nhiều hơn len(data) = file bị cắt giữa chừng.
    orig_len lớn hơn len(data) = tcpdump chạy với snaplen nhỏ (không phải lỗi).
    """
    incl = len(data) if incl_len is None else incl_len
    orig = len(data) if orig_len is None else orig_len
    return struct.pack(_endian(magic) + "IIII", ts_sec, ts_frac, incl, orig) + data


def write_pcap(tmp_path, body=b"", magic=MAGIC_USEC_LE, linktype=1, name="in.pcap"):
    """Global header 24 byte + phần thân đã dựng sẵn."""
    # HH = version 2.4 · i = thiszone (có dấu) · I = sigfigs · I = snaplen · I = linktype
    header = magic + struct.pack(_endian(magic) + "HHiIII", 2, 4, 0, 0, 65535, linktype)
    path = tmp_path / name
    path.write_bytes(header + body)
    return path


# --- đọc đúng nội dung ------------------------------------------------------

def test_order_and_ts(tmp_path):
    """REQ-2.1, 2.2: đúng thứ tự ghi, timestamp lấy từ bản ghi."""
    body = (
        record(b"aaa", ts_sec=1790486523, ts_frac=1)
        + record(b"bb", ts_sec=1790486524, ts_frac=2)
        + record(b"c", ts_sec=1790486525, ts_frac=3)
    )
    frames = list(PcapSource(write_pcap(tmp_path, body)).frames())
    assert [f.data for f in frames] == [b"aaa", b"bb", b"c"]
    assert [f.ts_sec for f in frames] == [1790486523, 1790486524, 1790486525]
    assert [f.ts_usec for f in frames] == [1, 2, 3]


def test_frame_metadata(tmp_path):
    path = write_pcap(tmp_path, record(FRAME, ts_sec=1, ts_frac=2), linktype=1)
    frame = next(iter(PcapSource(path).frames()))
    assert frame.source == "pcap"
    assert frame.linktype == 1
    assert frame.wire_len == len(FRAME)
    assert frame.truncated is False


def test_linktype_comes_from_global_header(tmp_path):
    """Linktype của file áp cho mọi bản ghi — pipeline dùng nó để chọn parser."""
    path = write_pcap(tmp_path, record(b"x"), linktype=113)
    assert [f.linktype for f in PcapSource(path).frames()] == [113]


def test_snaplen_cut_is_not_truncated(tmp_path):
    """orig_len > số byte có: tcpdump cắt theo snaplen, bản ghi vẫn nguyên vẹn."""
    body = record(b"\x00" * 40, orig_len=1514)
    frame = next(iter(PcapSource(write_pcap(tmp_path, body)).frames()))
    assert frame.wire_len == 1514
    assert len(frame.data) == 40
    assert frame.truncated is False


def test_empty_pcap_yields_nothing(tmp_path):
    assert list(PcapSource(write_pcap(tmp_path)).frames()) == []


def test_frames_starts_over_each_call(tmp_path):
    """Mỗi lần gọi frames() mở lại file -> chạy lại ra đúng cùng dữ liệu (NFR-2)."""
    source = PcapSource(write_pcap(tmp_path, record(b"a") + record(b"b")))
    assert [f.data for f in source.frames()] == [b"a", b"b"]
    assert [f.data for f in source.frames()] == [b"a", b"b"]


# --- endian và độ phân giải thời gian ---------------------------------------

def test_big_endian_magic(tmp_path):
    body = record(b"zz", ts_sec=258, ts_frac=772, magic=MAGIC_USEC_BE)
    path = write_pcap(tmp_path, body, magic=MAGIC_USEC_BE)
    frame = next(iter(PcapSource(path).frames()))
    assert (frame.ts_sec, frame.ts_usec) == (258, 772)
    assert frame.data == b"zz"


def test_nanosecond_pcap_divides_by_1000(tmp_path):
    body = record(b"n", ts_sec=7, ts_frac=123_456_789, magic=MAGIC_NANO_LE)
    path = write_pcap(tmp_path, body, magic=MAGIC_NANO_LE)
    frame = next(iter(PcapSource(path).frames()))
    assert (frame.ts_sec, frame.ts_usec) == (7, 123_456)


@pytest.mark.parametrize("nanos, expected", [(999, 0), (1000, 1), (1999, 1), (999_999_999, 999_999)])
def test_nanosecond_rounds_down(tmp_path, nanos, expected):
    """Làm tròn xuống: 999_999_999 ns không được thành 1_000_000 µs (§5.1)."""
    body = record(b"n", ts_frac=nanos, magic=MAGIC_NANO_LE)
    path = write_pcap(tmp_path, body, magic=MAGIC_NANO_LE, name=f"n{nanos}.pcap")
    assert next(iter(PcapSource(path).frames())).ts_usec == expected


def test_microsecond_pcap_keeps_value(tmp_path):
    """Cùng con số đó trong file micro giây thì KHÔNG được chia."""
    path = write_pcap(tmp_path, record(b"u", ts_frac=123_456))
    assert next(iter(PcapSource(path).frames())).ts_usec == 123_456


# --- bản ghi cụt (REQ-2.5) ---------------------------------------------------

def test_truncated_last_record(tmp_path):
    """File bị cắt giữa bản ghi cuối: không ném, đánh dấu truncated."""
    body = record(b"\x11" * 10) + record(b"\x22" * 4, incl_len=40)
    frames = list(PcapSource(write_pcap(tmp_path, body)).frames())
    assert len(frames) == 2
    assert frames[0].truncated is False
    assert frames[1].truncated is True
    assert frames[1].data == b"\x22" * 4      # giữ phần đọc được


def test_record_header_cut_in_half_is_dropped(tmp_path):
    """Thiếu cả header 16 byte thì không còn gì để dựng bản ghi -> hết file."""
    body = record(b"ok") + struct.pack("<II", 5, 6)   # mới 8/16 byte header
    frames = list(PcapSource(write_pcap(tmp_path, body)).frames())
    assert [f.data for f in frames] == [b"ok"]


# --- từ chối file không dùng được (REQ-2.4, 17.4) ---------------------------

def test_pcapng_rejected(tmp_path):
    path = tmp_path / "capture.pcapng"
    path.write_bytes(MAGIC_PCAPNG + b"\x00" * 60)
    with pytest.raises(SourceError, match="PCAPNG"):
        PcapSource(path)


def test_text_file_rejected(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("day khong phai file pcap\n")
    with pytest.raises(SourceError, match="not a pcap file"):
        PcapSource(path)


def test_empty_file_rejected(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    with pytest.raises(SourceError):
        PcapSource(path)


def test_missing_file_message_has_the_name(tmp_path):
    """V3.2: người chạy phải đọc được tên file trong thông báo lỗi."""
    with pytest.raises(SourceError, match="khongcofile.pcap"):
        PcapSource(tmp_path / "khongcofile.pcap")


def test_directory_rejected(tmp_path):
    with pytest.raises(SourceError):
        PcapSource(tmp_path)


def test_global_header_cut_after_magic(tmp_path):
    """Magic đúng nhưng thiếu 20 byte còn lại -> SourceError, không phải lỗi Scapy."""
    path = tmp_path / "cut.pcap"
    path.write_bytes(MAGIC_USEC_LE + b"\x02\x00")
    source = PcapSource(path)          # magic hợp lệ nên bước này qua
    with pytest.raises(SourceError, match="cannot read pcap file"):
        list(source.frames())
