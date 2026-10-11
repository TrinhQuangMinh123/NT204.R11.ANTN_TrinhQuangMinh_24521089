"""Decoder — stage 1: đưa dữ liệu về dạng người/luật đọc được (REQ-21–25).

Bảng tra Phụ lục F ở dạng dữ liệu (`_ROWS`): mỗi dòng là một phép decode gắn với
một khoá đích trong `event["decode"]`. Thêm một phép decode = thêm một dòng + một
hàm `_decode_*`, không sửa hàm cũ (NFR-15). Decoder chỉ ĐIỀN năm khoá con đã dựng
sẵn trong `new_event()` (ADR-19) và tổng hợp `decode.status`.

F4 (HTML entity) chồng LÊN kết quả F1/F2/F3 nên các dòng đó ghi `rule` = "F1+F4"…
Giải mã không bao giờ là "lỗi": `app_proto` null/UNKNOWN/DNS hay payload rỗng →
mọi khoá `not_applicable`, KHÔNG ghi gì vào `errors` (REQ-25.2).

Chỉ import idps.core và idps.process (chain, codecs) — tầng process/ vẫn độc lập
với capture/decode (I-20).
"""
import base64
import re

from .chain import Stage
from .codecs import (
    aggregate_status,
    decoded,
    entity_decode,
    form_decode,
    mime_decode,
    percent_decode,
    to_text,
)

# Năm khoá con của event["decode"], đúng §5.2 — thứ tự để tổng hợp status.
_FIELDS = ("uri", "query", "body_form", "body_text", "mime")

# Dấu hiệu "packet SMTP này có MIME": một header MIME xuất hiện ở đầu dòng. Lọc
# packet lệnh/đáp (MAIL FROM, 250 OK…) ra khỏi F6 — chúng không mang nội dung thư.
_MIME_HEADER_RE = re.compile(
    rb"(?im)^(?:content-type|content-transfer-encoding|mime-version)[ \t]*:"
)


def _http_app(event):
    """event["app"] nếu đây là HTTP đã parse được, ngược lại None."""
    if event.get("app_proto") == "HTTP" and event.get("app"):
        return event["app"]
    return None


def _content_type(app):
    for name, value in app.get("headers", []):
        if name.lower() == "content-type":
            return value
    return None


def _overlay_entity(base, rule):
    """F4 trên một chuỗi: giải entity lên `base.value`, nối rule "<rule>+F4".

    base là DecodedValue của F1 (percent). Nếu F1 đã bỏ (value None, vd vượt giới
    hạn) thì không chồng entity — giữ rule gốc và status/reasons của F1.
    """
    if base["value"] is None:
        return decoded(None, rule, base["status"], base["reasons"])
    ent = entity_decode(base["value"])
    status = aggregate_status([base["status"], ent["status"]])
    return decoded(ent["value"], f"{rule}+F4", status, base["reasons"] + ent["reasons"])


def _overlay_entity_pairs(base, rule):
    """F4 trên danh sách cặp [tên, giá trị]: giải entity cho từng GIÁ TRỊ (F2/F3)."""
    if base["value"] is None:
        return decoded(None, rule, base["status"], base["reasons"])
    reasons = list(base["reasons"])
    statuses = [base["status"]]
    out = []
    for name, value in base["value"]:
        ent = entity_decode(value)
        out.append([name, ent["value"]])
        statuses.append(ent["status"])
        reasons += ent["reasons"]
    return decoded(out, f"{rule}+F4", aggregate_status(statuses), reasons)


def _decode_uri(event, limit):
    """F1(+F4): percent-decode URI rồi giải entity."""
    app = _http_app(event)
    if not app or not app.get("uri"):
        return None
    return _overlay_entity(percent_decode(app["uri"], limit), "F1")


def _decode_query(event, limit):
    """F2(+F4): tách cặp của phần query rồi giải entity từng giá trị."""
    app = _http_app(event)
    if not app or not app.get("uri") or "?" not in app["uri"]:
        return None
    query = app["uri"].split("?", 1)[1]
    return _overlay_entity_pairs(form_decode(query, limit), "F2")


def _decode_body_form(event, limit):
    """F3(+F4): body `application/x-www-form-urlencoded` → cặp đã giải entity."""
    app = _http_app(event)
    if not app or not app.get("body_b64"):
        return None
    content_type = (_content_type(app) or "").lower()
    if not content_type.startswith("application/x-www-form-urlencoded"):
        return None
    body = base64.b64decode(app["body_b64"]).decode("latin-1")
    return _overlay_entity_pairs(form_decode(body, limit), "F3")


def _decode_body_text(event, limit):
    """F5: body `text/*` → text an toàn (ADR-21) rồi giải entity."""
    app = _http_app(event)
    if not app or not app.get("body_b64"):
        return None
    content_type = (_content_type(app) or "").lower()
    if not content_type.startswith("text/"):
        return None
    raw = base64.b64decode(app["body_b64"])
    if len(raw) > limit:
        return decoded(None, "F5", "partial", [f"input_over_max_decode_bytes={limit}"])
    text = to_text(raw)
    ent = entity_decode(text["value"])
    status = aggregate_status([text["status"], ent["status"]])
    return decoded(ent["value"], "F5", status, text["reasons"] + ent["reasons"])


def _decode_mime(event, limit):
    """F6: payload SMTP có header MIME → bóc tách + giải Base64/QP ở mức packet.

    Chỉ áp khi payload thực sự mang MIME (lọc packet lệnh/đáp). mime_decode tự phân
    biệt ok (có cả header + body) với deferred_to_flow (thiếu dòng trống → REQ-23.5).
    """
    if event.get("app_proto") != "SMTP":
        return None
    tcp = event.get("tcp")
    if not tcp or not tcp.get("payload_b64"):
        return None
    payload = base64.b64decode(tcp["payload_b64"])
    if not _MIME_HEADER_RE.search(payload):
        return None
    return mime_decode(payload, limit)


# Bảng tra Phụ lục F: (khoá đích, hàm decode). Thứ tự khớp _FIELDS.
_ROWS = (
    ("uri", _decode_uri),
    ("query", _decode_query),
    ("body_form", _decode_body_form),
    ("body_text", _decode_body_text),
    ("mime", _decode_mime),
)


class Decoder(Stage):
    """Điền event["decode"]; không bao giờ chặn (decode không phải cổng an toàn)."""

    name = "decoder"

    def __init__(self, config):
        self.config = config

    def process(self, event):
        decode = event["decode"]
        limit = self.config["max_decode_bytes"]
        for target, run in _ROWS:
            result = run(event, limit)
            if result is not None:
                decode[target] = result
        # Tổng hợp theo thang nghiêm trọng §5.1; mọi khoá rỗng → not_applicable.
        decode["status"] = aggregate_status([decode[f]["status"] for f in _FIELDS])
        return True
