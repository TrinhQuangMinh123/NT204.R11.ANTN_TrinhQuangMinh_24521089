"""T2.1 — Preprocessor validation: valid/partial/invalid (REQ-26, Phụ lục G).

Normalization (T2.2) và policy/gate (T2.3) thêm test ở commit sau.
"""
from idps.core.event import new_event
from idps.core.frame import RawFrame
from idps.process.config import Config
from idps.process.preprocessor import Preprocessor

CFG = Config.load()


def base_event(**overrides):
    """Event TCP sạch, đủ 5-tuple — điểm xuất phát để bớt từng field trong test."""
    event = new_event(RawFrame(b"\x00" * 14, 1790486523, 123456, 60, 1, "pcap"), 1)
    event["transport_proto"] = "TCP"
    event["src_ip"], event["dst_ip"] = "10.10.0.10", "10.20.0.10"
    event["src_port"], event["dst_port"] = 54321, 80
    event.update(overrides)
    return event


def run(event):
    assert Preprocessor(CFG).process(event) is True
    return event["preprocess"]


# --- valid ------------------------------------------------------------------

def test_clean_event_is_valid():
    pp = run(base_event())
    assert pp["status"] == "valid"
    assert pp["reasons"] == []


# --- G.1 field bắt buộc thiếu -> invalid (REQ-26.4) ------------------------

def test_missing_each_required_field_is_invalid():
    for field in ("schema_version", "packet_id", "timestamp", "status"):
        event = base_event()
        event[field] = None
        pp = run(event)
        assert pp["status"] == "invalid", field
        assert any(field in r for r in pp["reasons"]), field


# --- G.2 field flow thiếu -> KHÔNG invalid (REQ-28.5) ----------------------

def test_missing_flow_field_is_not_invalid():
    event = base_event()
    event["src_port"] = None          # thiếu field G.2 -> xử lý ở Phase 3
    pp = run(event)
    assert pp["status"] != "invalid"


# --- port ngoài khoảng / sai kiểu -> invalid, nêu kiểu (REQ-26.5) ----------

def test_port_out_of_range_is_invalid():
    pp = run(base_event(src_port=70000))
    assert pp["status"] == "invalid"
    assert any("src_port" in r and "65535" in r for r in pp["reasons"])


def test_port_wrong_type_names_actual_type():
    pp = run(base_event(src_port="80"))     # chuỗi, không phải số (ca REQ-38.7)
    assert pp["status"] == "invalid"
    assert any("src_port" in r and "type str" in r for r in pp["reasons"])


def test_port_bool_is_invalid():
    pp = run(base_event(dst_port=True))     # bool là int con -> phải loại
    assert pp["status"] == "invalid"


# --- timestamp sai dạng -> invalid -----------------------------------------

def test_bad_timestamp_format_is_invalid():
    pp = run(base_event(timestamp="2026-10-11 05:22:03"))   # thiếu T/.ffffffZ
    assert pp["status"] == "invalid"
    assert any("timestamp" in r for r in pp["reasons"])


def test_numeric_timestamp_names_type():
    pp = run(base_event(timestamp=1790486523))
    assert pp["status"] == "invalid"
    assert any("timestamp" in r and "type int" in r for r in pp["reasons"])


# --- tên proto lạ -> invalid; UNKNOWN -> partial (REQ-28.4) ----------------

def test_unknown_proto_name_is_invalid():
    pp = run(base_event(app_proto="FTP"))
    assert pp["status"] == "invalid"


def test_unknown_app_proto_is_partial_not_invalid():
    pp = run(base_event(app_proto="UNKNOWN"))
    assert pp["status"] == "partial"
    assert any("unsupported" in r and "app_proto" in r for r in pp["reasons"])


def test_unknown_transport_is_partial():
    pp = run(base_event(transport_proto="UNKNOWN"))
    assert pp["status"] == "partial"


# --- dữ liệu bài 1 đánh dấu không đọc trọn -> partial (REQ-26.3) -----------

def test_upstream_malformed_is_partial():
    pp = run(base_event(status="malformed"))
    assert pp["status"] == "partial"
    assert any("malformed" in r for r in pp["reasons"])
