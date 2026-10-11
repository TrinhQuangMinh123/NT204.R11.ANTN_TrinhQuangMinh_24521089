"""Preprocessor — stage 2: kiểm tra, chuẩn hoá, gắn nhãn (REQ-26–29, Phụ lục G).

Flow Tracker chỉ nên nhận event có dữ liệu dùng được, nên stage này:
  1. Kiểm field bắt buộc G.1, khoảng giá trị G.4 → `invalid` nếu sai (REQ-26).
  2. Chuẩn hoá (THÊM trường, không ghi đè) để luật phát hiện viết một lần khớp
     mọi biến thể kiểu chữ/định dạng (REQ-27) — điền ở T2.2.
  3. Áp `missing_data_policy`, gắn `status`/`action`/`reasons` cho MỌI event, và
     chặn event `invalid`/`skipped` khỏi Flow Tracker nhưng VẪN cho ghi ra tệp
     (REQ-28, REQ-29) — điền ở T2.3.

Chỉ import idps.core và idps.process — tầng process/ độc lập với capture/decode (I-20).
"""
import re

from .chain import Stage

# timestamp hợp lệ: YYYY-MM-DDTHH:MM:SS.ffffffZ (G.4, bài 1 Q10/ADR-7).
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

_REQUIRED = ("schema_version", "packet_id", "timestamp", "status")  # G.1
_TRANSPORT_NAMES = ("TCP", "UDP", "UNKNOWN")                        # G.4 (+ null)
_APP_NAMES = ("HTTP", "DNS", "SMTP", "UNKNOWN")                     # G.4 (+ null)


def _type_name(value):
    return type(value).__name__


def _validate(event):
    """Trả danh sách lý do khiến event `invalid` (rỗng = qua kiểm). Không ném.

    Chỉ những field BẮT BUỘC (G.1) thiếu/sai, hoặc giá trị CÓ MẶT mà ngoài khoảng
    G.4, mới làm invalid. Field flow (G.2) thiếu KHÔNG invalid — chúng để flow_id
    = null ở Phase 3 (REQ-28.5). Lý do nêu tên field và KIỂU THỰC TẾ (REQ-26.5).
    """
    reasons = []
    for field in _REQUIRED:
        if event.get(field) is None:
            reasons.append(f"missing required field: {field}")

    packet_id = event.get("packet_id")
    if packet_id is not None and (
        isinstance(packet_id, bool) or not isinstance(packet_id, int) or packet_id < 1
    ):
        reasons.append(
            f"invalid packet_id: {packet_id!r} "
            f"(type {_type_name(packet_id)}, expected integer >= 1)"
        )

    timestamp = event.get("timestamp")
    if timestamp is not None and (
        not isinstance(timestamp, str) or not _TS_RE.match(timestamp)
    ):
        reasons.append(
            f"invalid timestamp: {timestamp!r} "
            f"(type {_type_name(timestamp)}, expected ISO 8601 UTC microseconds)"
        )

    for field in ("src_port", "dst_port"):
        port = event.get(field)
        if port is not None and (
            isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535
        ):
            reasons.append(
                f"invalid {field}: {port!r} "
                f"(type {_type_name(port)}, expected integer in [0,65535])"
            )

    transport = event.get("transport_proto")
    if transport is not None and transport not in _TRANSPORT_NAMES:
        reasons.append(f"invalid transport_proto: {transport!r}")
    app = event.get("app_proto")
    if app is not None and app not in _APP_NAMES:
        reasons.append(f"invalid app_proto: {app!r}")
    return reasons


def _soft_reasons(event):
    """Lý do khiến event `partial` (không `invalid`): proto UNKNOWN (REQ-28.4) và
    dữ liệu bài 1 đã đánh dấu không đọc trọn (`malformed`/`unknown` — REQ-26.3)."""
    reasons = []
    if event.get("transport_proto") == "UNKNOWN":
        reasons.append("unsupported: transport_proto=UNKNOWN")
    if event.get("app_proto") == "UNKNOWN":
        reasons.append("unsupported: app_proto=UNKNOWN")
    if event.get("status") in ("malformed", "unknown"):
        reasons.append(f"upstream_status={event['status']}")
    return reasons


class Preprocessor(Stage):
    """Gắn nhãn và (T2.2/T2.3) chuẩn hoá + chặn. `process()` chưa chặn ở T2.1."""

    name = "preprocessor"

    def __init__(self, config):
        self.config = config

    def process(self, event):
        pp = event["preprocess"]
        invalid = _validate(event)
        if invalid:
            pp["status"] = "invalid"
            pp["reasons"] = invalid
            return True
        soft = _soft_reasons(event)
        pp["status"] = "partial" if soft else "valid"
        pp["reasons"] = soft
        return True
