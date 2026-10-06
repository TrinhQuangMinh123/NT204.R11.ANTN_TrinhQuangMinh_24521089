"""T0.3 — Config: mặc định, tệp, --set, kiểm tra, in lại (REQ-36, ADR-24)."""
import json
from pathlib import Path

import pytest

from idps.process.config import Config, ConfigError

ROOT = Path(__file__).resolve().parent.parent

# Giá trị mặc định Phụ lục J — chép tay để test bắt được nếu ai đổi mặc định.
DEFAULTS = {
    "tcp.new": 60,
    "tcp.established": 3600,
    "tcp.closed": 120,
    "udp.new": 30,
    "udp.established": 300,
    "max_active_flows": 10000,
    "max_decode_bytes": 65536,
    "max_reassembly_bytes": 1048576,
    "max_reassembly_total_bytes": 16777216,
    "missing_data_policy": "mark",
}


def write(tmp_path, obj):
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


# --- mặc định và tệp -------------------------------------------------------

def test_defaults_without_file():
    cfg = Config.load()
    assert cfg.values == DEFAULTS


def test_default_file_roundtrips_to_defaults():
    """idps-config.json trong repo đúng giá trị mặc định (_comment bị bỏ qua)."""
    cfg = Config.load(str(ROOT / "idps-config.json"))
    assert cfg.values == DEFAULTS


def test_file_merges_with_defaults(tmp_path):
    cfg = Config.load(write(tmp_path, {"tcp": {"new": 5}}))
    assert cfg["tcp.new"] == 5            # từ tệp
    assert cfg["tcp.established"] == 3600  # mặc định giữ nguyên
    assert cfg["max_active_flows"] == 10000


def test_set_overrides_file(tmp_path):
    cfg = Config.load(write(tmp_path, {"tcp": {"new": 5}}), [("tcp.new", "9")])
    assert cfg["tcp.new"] == 9
    assert isinstance(cfg["tcp.new"], int)  # chuỗi "9" đã ép thành số


def test_comment_keys_ignored(tmp_path):
    cfg = Config.load(write(tmp_path, {
        "_comment": "giải thích",
        "tcp": {"_note": "ghi chú", "new": 5},
    }))
    assert cfg["tcp.new"] == 5


# --- khoá lạ ---------------------------------------------------------------

def test_unknown_nested_key(tmp_path):
    with pytest.raises(ConfigError) as exc:
        Config.load(write(tmp_path, {"tcp": {"nwe": 5}}))
    assert "unknown config parameter: tcp.nwe" in str(exc.value)


def test_unknown_toplevel_key(tmp_path):
    with pytest.raises(ConfigError) as exc:
        Config.load(write(tmp_path, {"bogus": 1}))
    assert "unknown config parameter: bogus" in str(exc.value)


def test_unknown_key_in_set():
    with pytest.raises(ConfigError) as exc:
        Config.load(None, [("tcp.nwe", "5")])
    assert "unknown config parameter: tcp.nwe" in str(exc.value)


# --- sai kiểu --------------------------------------------------------------

def test_wrong_type_from_file(tmp_path):
    with pytest.raises(ConfigError) as exc:
        Config.load(write(tmp_path, {"tcp": {"new": "x"}}))
    msg = str(exc.value)
    assert "tcp.new" in msg and "'x'" in msg and "number > 0" in msg


def test_wrong_type_from_set():
    with pytest.raises(ConfigError) as exc:
        Config.load(None, [("tcp.new", "x")])
    msg = str(exc.value)
    assert "invalid value for tcp.new" in msg and "'x'" in msg


def test_bool_rejected_for_number(tmp_path):
    """JSON true không được âm thầm thành 1 cho một tham số số."""
    with pytest.raises(ConfigError):
        Config.load(write(tmp_path, {"tcp": {"new": True}}))


def test_float_rejected_for_int(tmp_path):
    with pytest.raises(ConfigError) as exc:
        Config.load(write(tmp_path, {"max_active_flows": 1.5}))
    assert "max_active_flows" in str(exc.value)


# --- ngoài khoảng ----------------------------------------------------------

def test_zero_out_of_range_for_gt0():
    with pytest.raises(ConfigError) as exc:
        Config.load(None, [("tcp.new", "0")])
    msg = str(exc.value)
    assert "tcp.new" in msg and "0" in msg and "number > 0" in msg


def test_tcp_closed_allows_zero():
    cfg = Config.load(None, [("tcp.closed", "0")])
    assert cfg["tcp.closed"] == 0


def test_policy_invalid_value():
    with pytest.raises(ConfigError) as exc:
        Config.load(None, [("missing_data_policy", "drop")])
    msg = str(exc.value)
    assert "missing_data_policy" in msg and "drop" in msg and "mark, skip" in msg


def test_policy_valid_value():
    cfg = Config.load(None, [("missing_data_policy", "skip")])
    assert cfg["missing_data_policy"] == "skip"


# --- lỗi tệp ---------------------------------------------------------------

def test_missing_file_errors():
    with pytest.raises(ConfigError) as exc:
        Config.load("/nonexistent/idps-config.json")
    assert "cannot read config" in str(exc.value)


def test_invalid_json_errors(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        Config.load(str(path))
    assert "invalid config" in str(exc.value)


def test_non_object_json_errors(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        Config.load(str(path))
    assert "invalid config" in str(exc.value) and "object" in str(exc.value)


# --- in lại cấu hình (REQ-36.4) --------------------------------------------

def test_line_is_one_sorted_dotted_line():
    cfg = Config.load(None, [("tcp.new", "5")])
    line = cfg.line()
    assert line.startswith("config=")
    assert "\n" not in line
    assert '"tcp.new":5' in line  # khoá dạng chấm, giá trị là số
    body = json.loads(line[len("config="):])
    assert list(body) == sorted(body)         # sort_keys=True
    assert body["tcp.new"] == 5
    assert set(body) == set(DEFAULTS)         # đủ mọi tham số, không thừa thiếu
