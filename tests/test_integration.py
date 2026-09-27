"""T3.6 — main.py --pcap trên traffic thật của lab (I-7, I-8, I-10, NFR-3).

tests/data/lab_mixed.pcap bắt bằng tcpdump trong container `attacker`
(ADR-11) trong lúc chạy: curl http://10.20.0.10/, curl http://10.20.0.10:8081/,
dig @10.20.0.10 victim.lab A, và một phiên SMTP EHLO/QUIT tới 10.20.0.10:25.

Lệnh đã dùng (ghi lại để tái lập):
    docker compose exec -T attacker timeout 14 tcpdump -i eth0 -U -w - \
        'host 10.20.0.10 or arp' > tests/data/lab_mixed.pcap
File được commit nên test này tất định dù lab có chạy hay không.
"""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

from idps.capture.pcap import PcapSource
from idps.core.runner import Runner
from idps.core.sink import EventSink
from idps.decode.pipeline import process_frame
from idps.output.jsonl import JsonlWriter

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "main.py"
LAB_PCAP = Path(__file__).resolve().parent / "data" / "lab_mixed.pcap"

# magic -> thứ tự byte của máy đã ghi file
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}


def count_records(path):
    """Đếm bản ghi bằng cách tự đi trong file — KHÔNG dùng PcapSource.

    Dùng chính module đang kiểm để đếm thì test chỉ nói "code đồng ý với chính
    nó". Ở đây đi tay: bỏ 24 byte global header, mỗi bản ghi = 16 byte header
    (trong đó incl_len ở offset 8) + incl_len byte dữ liệu.
    """
    raw = path.read_bytes()
    endian = _MAGICS[raw[:4]]
    offset, count = 24, 0
    while offset + 16 <= len(raw):
        incl_len = struct.unpack_from(endian + "I", raw, offset + 8)[0]
        offset += 16 + incl_len
        count += 1
    return count


def run_cli(*args):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run(
        [sys.executable, str(MAIN), *[str(a) for a in args]],
        env=env, capture_output=True, text=True,
    )


def run_on_lab_pcap(out):
    result = run_cli("--pcap", LAB_PCAP, "-o", out)
    assert result.returncode == 0, result.stderr
    return result


def events_of(path):
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


# --- dữ liệu đầu vào --------------------------------------------------------

def test_lab_pcap_is_committed_and_classic():
    assert LAB_PCAP.exists(), "thiếu tests/data/lab_mixed.pcap"
    assert LAB_PCAP.read_bytes()[:4] in _MAGICS
    assert count_records(LAB_PCAP) > 0


# --- một event cho một packet (I-7, I-8) ------------------------------------

def test_line_count(tmp_path):
    """I-7: số dòng output = số bản ghi trong file."""
    out = tmp_path / "out.jsonl"
    run_on_lab_pcap(out)
    assert len(events_of(out)) == count_records(LAB_PCAP)


def test_packet_ids(tmp_path):
    """I-8: 1, 2, 3... liên tục, không nhảy cóc, không trùng."""
    out = tmp_path / "out.jsonl"
    run_on_lab_pcap(out)
    ids = [e["packet_id"] for e in events_of(out)]
    assert ids == list(range(1, len(ids) + 1))


def test_every_line_is_valid_json(tmp_path):
    """NFR-3: đọc từng dòng bằng json parser, 0 dòng lỗi."""
    out = tmp_path / "out.jsonl"
    run_on_lab_pcap(out)
    for line in out.read_text(encoding="ascii").splitlines():
        json.loads(line)


def test_every_event_has_the_same_keys(tmp_path, event_keys):
    """I-2 trên dữ liệu thật, không phải trên packet dựng tay."""
    out = tmp_path / "out.jsonl"
    run_on_lab_pcap(out)
    for event in events_of(out):
        assert tuple(event) == event_keys


def test_stats_line_matches_the_file(tmp_path):
    """V3.1: processed trong dòng thống kê = số dòng trong file."""
    out = tmp_path / "out.jsonl"
    result = run_on_lab_pcap(out)
    stats = dict(part.split("=") for part in result.stdout.split())
    assert int(stats["processed"]) == len(events_of(out))
    assert int(stats["processed"]) == count_records(LAB_PCAP)


# --- tái lập (I-10, NFR-2) ---------------------------------------------------

def test_deterministic(tmp_path):
    """Chạy hai lần trên cùng file -> hai output giống hệt TỪNG BYTE."""
    first, second = tmp_path / "1.jsonl", tmp_path / "2.jsonl"
    run_on_lab_pcap(first)
    run_on_lab_pcap(second)
    assert first.read_bytes() == second.read_bytes()


def test_timestamps_come_from_the_records(tmp_path):
    """REQ-2.2: timestamp là của bản ghi, không phải lúc chạy -> không giảm."""
    out = tmp_path / "out.jsonl"
    run_on_lab_pcap(out)
    stamps = [e["timestamp"] for e in events_of(out)]
    # Chuỗi ISO 8601 UTC đủ 6 chữ số: so sánh chuỗi ra đúng thứ tự thời gian.
    assert stamps == sorted(stamps)
    assert all(e["source"] == "pcap" for e in events_of(out))


# --- traffic thật thì không có packet hỏng ----------------------------------

def test_real_traffic_has_no_malformed_packet(tmp_path):
    out = tmp_path / "out.jsonl"
    run_on_lab_pcap(out)
    assert [e for e in events_of(out) if e["status"] == "malformed"] == []


# --- NFR-9: gắn thêm một module phía sau ------------------------------------

class CountingSink(EventSink):
    """Module giả của bài sau: chỉ đếm và nhớ thứ tự packet_id."""

    def __init__(self):
        self.ids = []
        self.closed = 0

    def handle(self, event):
        self.ids.append(event["packet_id"])

    def close(self):
        self.closed += 1


def test_extra_module_sees_every_event(tmp_path):
    """NFR-9: số event module nhận = số dòng JSON Lines, đúng thứ tự."""
    out = tmp_path / "out.jsonl"
    counter = CountingSink()
    stats = Runner(
        PcapSource(LAB_PCAP), [JsonlWriter(out), counter], process_frame
    ).run()

    assert counter.ids == list(range(1, stats.processed + 1))
    assert len(counter.ids) == len(events_of(out))
    assert counter.closed == 1          # REQ-20.3: được báo kết thúc
