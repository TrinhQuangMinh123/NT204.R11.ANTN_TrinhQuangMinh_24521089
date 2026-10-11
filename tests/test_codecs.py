"""T1.1 — codecs: percent-decode, form-urlencoded, text UTF-8 an toàn.

Mỗi ca đã đo ở ADR-20/ADR-21 là một test trực tiếp (chiến lược §9). entity_decode
và mime_decode có test riêng ở T1.2/T1.3.
"""
from idps.process.codecs import (
    decoded,
    entity_decode,
    form_decode,
    percent_decode,
    to_text,
)

LIMIT = 65536  # max_decode_bytes mặc định


# --- decoded() helper ------------------------------------------------------

def test_decoded_shape():
    dv = decoded("x", "F1", "ok")
    assert tuple(dv) == ("value", "rule", "status", "reasons")
    assert dv == {"value": "x", "rule": "F1", "status": "ok", "reasons": []}


def test_decoded_reasons_are_not_shared():
    a = decoded(None, None, "partial")
    b = decoded(None, None, "partial")
    a["reasons"].append("x")
    assert b["reasons"] == []


# --- percent_decode (F1) — I-14, REQ-21.5/21.6 -----------------------------

def test_percent_decode_once():
    dv = percent_decode("%2527", LIMIT)
    assert dv["value"] == "%27"       # một lần: %25 -> %, không đệ quy ra '
    assert dv["status"] == "ok"


def test_percent_decode_plain_attack_string():
    assert percent_decode("%27%20OR%201%3D1", LIMIT)["value"] == "' OR 1=1"


def test_percent_decode_invalid_escape_is_partial():
    dv = percent_decode("100%25 vs %ZZ %2", LIMIT)
    assert dv["value"] == "100% vs %ZZ %2"   # đoạn sai giữ nguyên
    assert dv["status"] == "partial"
    assert dv["reasons"]                      # có ít nhất một lý do


def test_percent_decode_does_not_turn_plus_into_space():
    # '+' chỉ là dấu cách trong form-urlencoded, không trong percent-decode.
    assert percent_decode("a+b", LIMIT)["value"] == "a+b"


def test_percent_decode_invalid_utf8_is_partial():
    dv = percent_decode("%FF", LIMIT)
    assert dv["status"] == "partial"
    assert dv["value"] == "�"
    assert any("utf8_invalid_byte_at=0" in r for r in dv["reasons"])


def test_percent_decode_over_limit_is_skipped():
    dv = percent_decode("%41" * 100, 10)
    assert dv["value"] is None
    assert any("10" in r for r in dv["reasons"])


# --- form_decode (F2/F3) — REQ-21.3/21.4 -----------------------------------

def test_form_decode_pairs_and_blanks():
    dv = form_decode("a=1&b=2&c=&d", LIMIT)
    assert dv["value"] == [["a", "1"], ["b", "2"], ["c", ""], ["d", ""]]
    assert dv["status"] == "ok"


def test_form_decode_plus_is_space():
    assert form_decode("q=a+b", LIMIT)["value"] == [["q", "a b"]]


def test_form_decode_percent_in_value():
    assert form_decode("q=%27+OR", LIMIT)["value"] == [["q", "' OR"]]


def test_form_decode_invalid_escape_is_partial():
    dv = form_decode("q=%ZZ", LIMIT)
    assert dv["status"] == "partial"
    assert dv["reasons"]


def test_form_decode_over_limit_is_skipped():
    dv = form_decode("a=1&" * 100, 10)
    assert dv["value"] is None
    assert any("10" in r for r in dv["reasons"])


# --- to_text (ADR-21, REQ-24.2) --------------------------------------------

def test_to_text_valid_ascii():
    dv = to_text(b"abc")
    assert dv["value"] == "abc"
    assert dv["status"] == "ok"
    assert dv["reasons"] == []


def test_to_text_invalid_byte_is_partial():
    dv = to_text(b"ok\xffbad")
    assert dv["status"] == "partial"
    assert dv["value"] == "ok�bad"          # U+FFFD thay byte lỗi
    assert "utf8_invalid_byte_at=2" in dv["reasons"][0]
    assert "value=0xFF" in dv["reasons"][0]


def test_to_text_does_not_raise_on_any_bytes():
    for data in (b"", b"\x00", bytes(range(256))):
        to_text(data)  # không ném


# --- entity_decode (F4/F5) — REQ-22, ADR-27 --------------------------------

def test_entity_decode_once():
    dv = entity_decode("&amp;lt;")
    assert dv["value"] == "&lt;"        # một lần: &amp;->& , KHÔNG giải tiếp ra <
    assert dv["status"] == "ok"


def test_entity_decode_well_formed_is_ok():
    dv = entity_decode("&lt;script&gt;")
    assert dv["value"] == "<script>"
    assert dv["status"] == "ok"


def test_entity_missing_semicolon_is_decoded_and_partial():
    dv = entity_decode("&ltscript&gt")           # thiếu `;`, khớp luật HTML5
    assert dv["value"] == "<script>"
    assert dv["status"] == "partial"
    assert dv["reasons"]


def test_entity_longest_match_leaves_remainder():
    dv = entity_decode("&notit;")                # &not -> ¬, còn 'it;'
    assert dv["value"] == "¬it;"
    assert dv["status"] == "partial"


def test_entity_unknown_name_kept_verbatim():
    dv = entity_decode("&bogus;")
    assert dv["value"] == "&bogus;"              # giữ nguyên (REQ-22.5)
    assert dv["status"] == "partial"
    assert dv["reasons"]


def test_entity_numeric_forms():
    dv = entity_decode("&#60;&#x3E;")
    assert dv["value"] == "<>"
    assert dv["status"] == "ok"


def test_entity_plain_ampersand_not_flagged():
    for text in ("Tom & Jerry", "AT&T", "a=1&b=2"):
        dv = entity_decode(text)
        assert dv["status"] == "ok", text
        assert dv["reasons"] == []
