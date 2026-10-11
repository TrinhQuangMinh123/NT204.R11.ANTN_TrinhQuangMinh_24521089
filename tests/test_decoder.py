"""T1.4 — Decoder stage: mỗi dòng Phụ lục F1–F6, tổng hợp status, rule, errors."""
from idps.core.event import b64, new_event
from idps.core.frame import RawFrame
from idps.process.codecs import aggregate_status
from idps.process.config import Config
from idps.process.decoder import Decoder

CFG = Config.load()


def _frame():
    return RawFrame(b"\x00" * 14, 1790486523, 0, 60, 1, "pcap")


def http_event(uri="/", headers=None, body=b""):
    event = new_event(_frame(), 1)
    event["app_proto"] = "HTTP"
    event["app"] = {
        "kind": "request", "method": "GET", "uri": uri, "version": "HTTP/1.1",
        "status_code": None, "reason": None, "headers": headers or [],
        "body_len": len(body), "body_b64": b64(body), "incomplete": False,
    }
    return event


def smtp_event(payload=b""):
    event = new_event(_frame(), 1)
    event["app_proto"] = "SMTP"
    event["tcp"] = {"payload_len": len(payload), "payload_b64": b64(payload)}
    return event


def run(event):
    assert Decoder(CFG).process(event) is True   # Decoder không bao giờ chặn
    return event["decode"]


# --- F1: percent-decode URI (REQ-21.1, 21.5) -------------------------------

def test_f1_uri_percent_decode():
    d = run(http_event(uri="/?q=%27%20OR%201%3D1"))
    assert d["uri"]["value"] == "/?q=' OR 1=1"
    assert d["status"] == "ok"


# --- F2: query thành cặp (REQ-21.3) ----------------------------------------

def test_f2_query_pairs():
    d = run(http_event(uri="/p?a=%27+OR&b=2"))
    assert d["query"]["value"] == [["a", "' OR"], ["b", "2"]]


def test_f2_absent_without_question_mark():
    d = run(http_event(uri="/plain"))
    assert d["query"]["value"] is None            # không có '?' -> không áp dụng
    assert d["query"]["status"] == "not_applicable"


# --- F3: body form-urlencoded (REQ-21.4) -----------------------------------

def test_f3_body_form():
    event = http_event(
        headers=[["Content-Type", "application/x-www-form-urlencoded"]],
        body=b"user=%27+OR&pw=x",
    )
    d = run(event)
    assert d["body_form"]["value"] == [["user", "' OR"], ["pw", "x"]]


# --- F4: entity chồng lên F1 (REQ-22.1, 22.6) ------------------------------

def test_f4_entity_overlays_uri():
    d = run(http_event(uri="/?x=&lt;script&gt;"))
    assert d["uri"]["value"] == "/?x=<script>"
    assert d["uri"]["rule"] == "F1+F4"


# --- F5: body text/* (REQ-22.1, 24.1) --------------------------------------

def test_f5_body_text():
    event = http_event(headers=[["Content-Type", "text/html"]], body=b"<p>&amp;</p>")
    d = run(event)
    assert d["body_text"]["value"] == "<p>&</p>"   # entity một lần: &amp; -> &
    assert d["body_text"]["rule"] == "F5"
    assert d["body_text"]["status"] == "ok"


# --- F6: MIME của SMTP (REQ-23.1) ------------------------------------------

def test_f6_mime_base64():
    payload = (b"Content-Type: text/plain\r\n"
               b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=")
    d = run(smtp_event(payload))
    assert d["mime"]["rule"] == "F6"
    assert d["mime"]["value"]["parts"][0]["text"] == "Hello"
    assert d["status"] == "ok"


def test_f6_skips_smtp_command_packet():
    d = run(smtp_event(b"MAIL FROM:<a@b.test>\r\n"))
    assert d["mime"]["value"] is None             # không có header MIME -> không áp
    assert d["status"] == "not_applicable"


# --- rule nối (REQ-25.4) ----------------------------------------------------

def test_rule_recorded_as_f1_plus_f4():
    d = run(http_event(uri="/a"))
    assert d["uri"]["rule"] == "F1+F4"


# --- tổng hợp status (REQ-25.1, 25.2) --------------------------------------

def test_aggregate_rule_most_severe_wins():
    assert aggregate_status(["invalid", "ok"]) == "invalid"
    assert aggregate_status(["not_applicable"] * 5) == "not_applicable"


def test_partial_uri_makes_decode_partial():
    d = run(http_event(uri="/?q=%ZZ"))
    assert d["uri"]["status"] == "partial"
    assert d["status"] == "partial"


def test_invalid_mime_makes_decode_invalid():
    payload = b"Content-Transfer-Encoding: base64\r\n\r\nSGVs*bG8="
    d = run(smtp_event(payload))
    assert d["mime"]["value"]["parts"][0]["status"] == "invalid"
    assert d["status"] == "invalid"


# --- not_applicable không phải lỗi (REQ-25.2) ------------------------------

def test_dns_is_not_applicable_and_no_error():
    event = new_event(_frame(), 1)
    event["app_proto"] = "DNS"
    event["app"] = {"questions": [], "answers": []}
    out = Decoder(CFG).process(event)
    assert out is True
    assert event["decode"]["status"] == "not_applicable"
    assert event["decode"]["reasons"] == []
    assert event["errors"] == []                 # KHÔNG ghi lỗi


def test_unknown_and_empty_are_not_applicable():
    for proto in ("UNKNOWN", None):
        event = new_event(_frame(), 1)
        event["app_proto"] = proto
        d = run(event)
        assert d["status"] == "not_applicable"
        assert all(d[f]["value"] is None for f in ("uri", "query", "body_form", "mime"))
