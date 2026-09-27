"""T3.5 — main.py chế độ PCAP: exit code, file output, dòng thống kê.

Chạy bằng subprocess chứ không gọi hàm: exit code và stderr là một phần hợp
đồng của chương trình (design §5.5), gọi main() trực tiếp thì không kiểm được
đường argparse tự thoát.
"""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import main as cli

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "main.py"

ETH = bytes.fromhex("02420a14000a" "02420a0a000a" "0800")
IPV4_STUB = ETH + b"\x45\x00nothing-below-yet"
ARP = bytes.fromhex("02420a14000a" "02420a0a000a" "0806") + b"arp"


def write_pcap(path, frames, last_incl_len=None):
    """PCAP micro giây little-endian, linktype 1 — chỉ cần một file vào hợp lệ.

    last_incl_len: khai độ dài lớn hơn thực có ở bản ghi cuối = file bị cắt.
    """
    # I = magic · HH = version 2.4 · i = thiszone · I = sigfigs · I = snaplen · I = linktype
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, data in enumerate(frames, start=1):
        incl = len(data)
        if last_incl_len is not None and i == len(frames):
            incl = last_incl_len
        out += struct.pack("<IIII", 1790486520 + i, i, incl, len(data)) + data
    path.write_bytes(bytes(out))
    return path


def run_cli(*args, cwd=None):
    # PYTHONPATH: test chạy với cwd là thư mục tạm nên package idps không nằm
    # trên đường import mặc định của tiến trình con.
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run(
        [sys.executable, str(MAIN), *[str(a) for a in args]],
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
    )


def lines_of(path):
    return path.read_text(encoding="ascii").splitlines()


# --- cú pháp tham số: exit 2 (REQ-3.3) --------------------------------------

def test_mode_exclusive_both(tmp_path):
    result = run_cli("--interface", "int0", "--pcap", "x.pcap")
    assert result.returncode == 2
    assert "usage" in result.stderr.lower()


def test_mode_exclusive_neither():
    result = run_cli()
    assert result.returncode == 2
    assert "usage" in result.stderr.lower()


def test_unknown_option():
    assert run_cli("--khong-co-option").returncode == 2


def test_help_exits_zero():
    result = run_cli("--help")
    assert result.returncode == 0
    assert "--pcap" in result.stdout and "--output" in result.stdout


# --- lỗi nguồn: exit 1 (REQ-2.4, 17.4) --------------------------------------

def test_missing_file(tmp_path):
    result = run_cli("--pcap", tmp_path / "khongcofile.pcap", "-o", tmp_path / "out.jsonl")
    assert result.returncode == 1
    assert "khongcofile.pcap" in result.stderr      # V3.2: thông báo nêu tên file
    assert result.stdout == ""                      # không in thống kê


def test_not_pcap(tmp_path):
    src = tmp_path / "notes.txt"
    src.write_text("day khong phai pcap\n")
    result = run_cli("--pcap", src, "-o", tmp_path / "out.jsonl")
    assert result.returncode == 1
    assert "not a pcap file" in result.stderr


def test_pcapng_rejected(tmp_path):
    src = tmp_path / "capture.pcapng"
    src.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    result = run_cli("--pcap", src, "-o", tmp_path / "out.jsonl")
    assert result.returncode == 1
    assert "PCAPNG" in result.stderr


def test_live_mode_is_not_implemented_yet(tmp_path):
    """Phase 4 thay bằng LiveSource; tới lúc đó phải báo rõ chứ không im lặng."""
    result = run_cli("--interface", "int0", "-o", tmp_path / "out.jsonl")
    assert result.returncode == 1
    assert "int0" in result.stderr


# --- lỗi output: exit 1 TRƯỚC khi đọc packet (REQ-13.4) ---------------------

def test_unwritable_output(tmp_path):
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB, ARP])
    result = run_cli("--pcap", src, "-o", tmp_path)     # thư mục, không phải file
    assert result.returncode == 1
    assert "cannot open output" in result.stderr
    assert "processed=" not in result.stdout            # chưa đọc packet nào


def test_output_directory_missing(tmp_path):
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB])
    result = run_cli("--pcap", src, "-o", tmp_path / "khong-co" / "out.jsonl")
    assert result.returncode == 1
    assert "processed=" not in result.stdout


def test_sink_that_fails_to_start_stops_the_run(monkeypatch, tmp_path):
    """REQ-20.4: module phía sau không mở được tài nguyên -> exit 1, chưa capture.

    Chạy trong tiến trình này để thay được JsonlWriter bằng một sink hỏng —
    đúng chỗ mà một module của bài sau sẽ cắm vào.
    """
    opened = []

    class BrokenSink:
        def __init__(self, path):
            raise OSError("khong mo duoc tai nguyen cua module phia sau")

    class SpySource:
        def __init__(self, path):
            opened.append(path)

    monkeypatch.setattr(cli, "JsonlWriter", BrokenSink)
    monkeypatch.setattr(cli, "PcapSource", SpySource)

    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB])
    assert cli.main(["--pcap", str(src), "-o", str(tmp_path / "out.jsonl")]) == 1
    assert opened == []          # nguồn chưa hề được mở


# --- đường chạy đúng (REQ-2.3, 13.1, 13.5) ----------------------------------

def test_stats_line(tmp_path):
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB, ARP, b"\x00" * 3])
    out = tmp_path / "out.jsonl"
    result = run_cli("--pcap", src, "-o", out)
    assert result.returncode == 0
    assert result.stdout.strip() == "processed=3 unknown=1 malformed=1"


def test_one_line_per_packet(tmp_path):
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB] * 5)
    out = tmp_path / "out.jsonl"
    assert run_cli("--pcap", src, "-o", out).returncode == 0
    lines = lines_of(out)
    assert len(lines) == 5
    assert [json.loads(line)["packet_id"] for line in lines] == [1, 2, 3, 4, 5]


def test_long_and_short_output_option_agree(tmp_path):
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB, ARP])
    long_out, short_out = tmp_path / "long.jsonl", tmp_path / "short.jsonl"
    run_cli("--pcap", src, "--output", long_out)
    run_cli("--pcap", src, "-o", short_out)
    assert long_out.read_bytes() == short_out.read_bytes()


def test_default_output(tmp_path):
    """Không truyền -o -> events.jsonl trong thư mục làm việc (REQ-13.6)."""
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB])
    result = run_cli("--pcap", src, cwd=tmp_path)
    assert result.returncode == 0
    assert len(lines_of(tmp_path / "events.jsonl")) == 1


def test_empty_pcap_still_exits_zero(tmp_path):
    src = write_pcap(tmp_path / "in.pcap", [])
    out = tmp_path / "out.jsonl"
    result = run_cli("--pcap", src, "-o", out)
    assert result.returncode == 0
    assert result.stdout.strip() == "processed=0 unknown=0 malformed=0"
    assert out.read_bytes() == b""


def test_truncated_record_does_not_stop_the_run(tmp_path):
    """REQ-2.5: bản ghi cuối bị cắt -> vẫn có event cho nó, vẫn exit 0."""
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB, IPV4_STUB], last_incl_len=9999)
    out = tmp_path / "out.jsonl"
    result = run_cli("--pcap", src, "-o", out)
    assert result.returncode == 0
    events = [json.loads(line) for line in lines_of(out)]
    assert len(events) == 2
    assert events[1]["errors"] == [{"layer": "capture", "reason": "truncated record"}]
    assert result.stdout.strip() == "processed=2 unknown=0 malformed=1"


def test_stats_line_matches_the_file(tmp_path):
    """V3.1: số trong dòng thống kê = số dòng trong file."""
    src = write_pcap(tmp_path / "in.pcap", [IPV4_STUB, ARP, IPV4_STUB, b"\x00" * 2])
    out = tmp_path / "out.jsonl"
    result = run_cli("--pcap", src, "-o", out)
    processed = int(result.stdout.split("processed=")[1].split()[0])
    assert processed == len(lines_of(out))
