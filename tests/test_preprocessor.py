"""T2.1 — Preprocessor validation: valid/partial/invalid (REQ-26, Phụ lục G).

Normalization (T2.2) và policy/gate (T2.3) thêm test ở commit sau.
"""
from idps.core.event import format_timestamp, new_event
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


def run(event, config=CFG):
    """Chạy Preprocessor, trả khoá preprocess. (T2.3: invalid/skip trả False —
    không assert giá trị trả ở đây; cổng chặn có test riêng.)"""
    Preprocessor(config).process(event)
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


# --- T2.2 chuẩn hoá (REQ-27, Phụ lục G.5) ----------------------------------

def http_event(uri="/", headers=None):
    event = base_event(app_proto="HTTP")
    event["app"] = {
        "kind": "request", "method": "GET", "uri": uri, "version": "HTTP/1.1",
        "status_code": None, "reason": None, "headers": headers or [],
        "body_len": 0, "body_b64": "", "incomplete": False,
    }
    return event


def test_ip_leading_zeros_stripped():
    pp = run(base_event(src_ip="010.020.000.010", dst_ip="10.20.0.10"))
    assert pp["src_ip"] == "10.20.0.10"
    assert pp["dst_ip"] == "10.20.0.10"


def test_protocol_uppercased():
    event = base_event(transport_proto="TCP", app_proto="HTTP")
    pp = run(event)
    assert pp["transport_proto"] == "TCP" and pp["app_proto"] == "HTTP"


def test_header_names_lowercased_same_count_and_order():
    event = http_event(headers=[["Host", "a"], ["Content-Type", "x"], ["host", "b"]])
    pp = run(event)
    assert pp["http_header_names"] == ["host", "content-type", "host"]
    # app.headers gốc KHÔNG đổi; tra theo chỉ số ra đúng tên gốc.
    assert event["app"]["headers"][0][0] == "Host"
    assert event["app"]["headers"][2][0] == "host"
    assert len(pp["http_header_names"]) == len(event["app"]["headers"])


def test_http_host_normalized_as_domain():
    pp = run(http_event(headers=[["Host", "Example.COM."]]))
    assert pp["http_host"] == "example.com"


def test_path_normalized_and_query_split():
    pp = run(http_event(uri="//a/./b/../c?q=1"))
    assert pp["path"] == "/a/c"
    assert pp["query_string"] == "q=1"


def test_original_uri_is_not_overwritten():
    event = http_event(uri="//a/./b/../c?q=1")
    run(event)
    assert event["app"]["uri"] == "//a/./b/../c?q=1"   # REQ-27.8


def test_path_traversal_above_root_stops_and_marks_partial():
    pp = run(http_event(uri="/../etc"))
    assert pp["status"] == "partial"
    assert any("path_traversal" in r for r in pp["reasons"])


def test_dns_names_lowercased_question_then_answer():
    event = base_event(app_proto="DNS")
    event["app"] = {
        "id": 1, "qr": "response", "opcode": "QUERY", "rcode": "NOERROR",
        "qdcount": 1, "ancount": 1,
        "questions": [{"name": "WWW.Example.COM.", "type": "A"}],
        "answers": [{"name": "WWW.Example.COM.", "type": "A", "ttl": 60, "data": "1.2.3.4"}],
    }
    pp = run(event)
    assert pp["dns_names"] == ["www.example.com", "www.example.com"]


def test_ts_usec_matches_timestamp_string():
    event = base_event(timestamp="2026-09-27T05:22:03.123456Z")
    pp = run(event)
    usec = pp["ts_usec"]
    assert isinstance(usec, int)
    assert format_timestamp(usec // 1_000_000, usec % 1_000_000) == "2026-09-27T05:22:03.123456Z"


# --- T2.3 metadata + policy + cổng chặn (REQ-28, REQ-29) -------------------

SKIP_CFG = Config.load(None, [("missing_data_policy", "skip")])
VALUES_STATUS = {"valid", "partial", "invalid"}
VALUES_ACTION = {"forwarded", "marked", "skipped"}


def test_valid_is_forwarded_with_no_reasons():
    keep = Preprocessor(CFG).process(ev := base_event())
    pp = ev["preprocess"]
    assert (pp["status"], pp["action"], pp["reasons"]) == ("valid", "forwarded", [])
    assert keep is True


def test_every_non_forwarded_event_has_a_reason():
    cases = [base_event(status="malformed"), base_event(src_port="x"),
             base_event(app_proto="UNKNOWN")]
    for event in cases:
        pp = run(event)
        if not (pp["status"] == "valid" and pp["action"] == "forwarded"):
            assert len(pp["reasons"]) >= 1          # REQ-29.3


def test_mark_policy_marks_and_continues():
    keep = Preprocessor(CFG).process(ev := base_event(status="malformed"))
    assert ev["preprocess"]["action"] == "marked"
    assert keep is True


def test_skip_policy_blocks_missing_data():
    keep = Preprocessor(SKIP_CFG).process(ev := base_event(status="malformed"))
    assert ev["preprocess"]["action"] == "skipped"
    assert ev["preprocess"]["reasons"]
    assert keep is False


def test_invalid_blocks_flow_tracker():
    keep = Preprocessor(CFG).process(ev := base_event(src_port=70000))
    assert ev["preprocess"]["status"] == "invalid"
    assert keep is False


def test_unknown_proto_continues_even_under_skip():
    # REQ-28.4: packet proto UNKNOWN là bằng chứng port scan -> vẫn xuống flow.
    keep = Preprocessor(SKIP_CFG).process(ev := base_event(app_proto="UNKNOWN"))
    assert ev["preprocess"]["status"] == "partial"
    assert ev["preprocess"]["action"] == "marked"
    assert keep is True


def test_status_and_action_use_fixed_vocabulary():
    cases = [base_event(), base_event(status="malformed"),
             base_event(app_proto="UNKNOWN"), base_event(src_port=70000)]
    for event in cases:
        pp = run(event)
        assert pp["status"] in VALUES_STATUS
        assert pp["action"] in VALUES_ACTION
