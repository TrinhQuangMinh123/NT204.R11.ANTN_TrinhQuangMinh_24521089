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
from datetime import datetime, timezone

from .chain import Stage

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

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


# --- chuẩn hoá (REQ-27, Phụ lục G.5) — luôn THÊM trường, không ghi đè (C-21) --

def _normalize_ipv4(ip):
    """Bỏ số 0 vô nghĩa đứng đầu mỗi octet: `010.020.000.010` → `10.20.0.10`.

    Không phải dotted-quad hợp lệ (IPv6, rác) → giữ nguyên: chuẩn hoá là bước AN
    TOÀN, không được đổi ý nghĩa dữ liệu không hiểu được (C-21).
    """
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        octets = [int(p) for p in parts]
        if all(0 <= o <= 255 for o in octets):
            return ".".join(str(o) for o in octets)
    return ip


def _normalize_domain(name):
    """Domain về chữ thường, bỏ dấu `.` cuối (REQ-27.3)."""
    return name.lower().rstrip(".")


def _normalize_path(uri):
    """URI → (path chuẩn hoá, query_string nguyên văn, lý do hoặc None).

    An toàn (REQ-27.5): gộp `//`, bỏ `/./`, giải `/../` TRONG phạm vi gốc; tách
    query. `/../` vượt gốc → DỪNG, giữ phần đã chuẩn hoá, ghi lý do — dấu hiệu
    path traversal không được âm thầm xoá (REQ-27.6, C-21). Không percent-decode:
    phần đã decode nằm ở `decode.query` (F2).
    """
    path_part, _, query = uri.partition("?")
    query_string = query if "?" in uri else None
    prefix = "/" if path_part.startswith("/") else ""
    out = []
    traversal = False
    for segment in path_part.split("/"):
        if segment in ("", "."):
            continue                       # gộp '//' và bỏ '/./'
        if segment == "..":
            if out:
                out.pop()                  # giải '/../' trong phạm vi gốc
            else:
                traversal = True           # vượt gốc -> dừng
                break
        else:
            out.append(segment)
    path = prefix + "/".join(out)
    reason = f"path_traversal_above_root: {path_part!r}" if traversal else None
    return path, query_string, reason


def _ts_usec(timestamp):
    """Chuỗi ISO 8601 → số nguyên micro giây từ epoch UTC (REQ-27.7).

    Số nguyên, KHÔNG qua float: cùng lý do ADR-7 của bài 1 — float mất micro giây
    ở độ lớn 1.79e9. delta.days/seconds/microseconds đều là số nguyên.
    """
    if not isinstance(timestamp, str):
        return None
    try:
        moment = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
    delta = moment.replace(tzinfo=timezone.utc) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _normalize(event):
    """Điền các trường chuẩn hoá vào event["preprocess"]; trả lý do `partial`
    của chuẩn hoá (hiện chỉ có path traversal). THÊM trường, không ghi đè (REQ-27.8).
    """
    pp = event["preprocess"]
    reasons = []

    transport = event.get("transport_proto")
    if isinstance(transport, str):
        pp["transport_proto"] = transport.upper()
    app_proto = event.get("app_proto")
    if isinstance(app_proto, str):
        pp["app_proto"] = app_proto.upper()
    if isinstance(event.get("src_ip"), str):
        pp["src_ip"] = _normalize_ipv4(event["src_ip"])
    if isinstance(event.get("dst_ip"), str):
        pp["dst_ip"] = _normalize_ipv4(event["dst_ip"])
    pp["ts_usec"] = _ts_usec(event.get("timestamp"))

    app = event.get("app")
    if app_proto == "HTTP" and app:
        headers = app.get("headers") or []
        # cùng số phần tử, cùng thứ tự với app.headers -> tra chỉ số ra tên gốc.
        pp["http_header_names"] = [name.lower() for name, _ in headers]
        for name, value in headers:
            if name.lower() == "host" and isinstance(value, str):
                pp["http_host"] = _normalize_domain(value)
                break
        if isinstance(app.get("uri"), str):
            pp["path"], pp["query_string"], reason = _normalize_path(app["uri"])
            if reason:
                reasons.append(reason)
    elif app_proto == "DNS" and app:
        names = [q.get("name") for q in app.get("questions") or []]
        names += [a.get("name") for a in app.get("answers") or []]
        pp["dns_names"] = [_normalize_domain(n) for n in names if isinstance(n, str)]

    return reasons


class Preprocessor(Stage):
    """Kiểm tra + chuẩn hoá + áp `missing_data_policy`, gắn status/action/reasons.

    Trả `False` để CHẶN khỏi Flow Tracker đúng hai ca: `invalid` (REQ-26.4) và
    `partial` do dữ liệu thiếu khi policy = `skip` (REQ-28.3). Chặn chỉ dừng các
    stage SAU trong chuỗi — event vẫn tới JsonlWriter (sink riêng) nên "bị bỏ qua
    vẫn để lại dấu vết" (ADR-17, REQ-28.3). Mọi event đều có đủ ba trường metadata.
    """

    name = "preprocessor"

    def __init__(self, config):
        self.config = config

    def process(self, event):
        pp = event["preprocess"]

        invalid = _validate(event)
        if invalid:
            pp["status"] = "invalid"
            pp["action"] = "skipped"      # không xuống Flow Tracker, vẫn được ghi
            pp["reasons"] = invalid
            return False

        reasons = _soft_reasons(event)
        reasons += _normalize(event)
        pp["reasons"] = reasons
        if not reasons:
            pp["status"] = "valid"
            pp["action"] = "forwarded"
            return True

        pp["status"] = "partial"
        # policy `skip` chỉ áp cho dữ liệu THIẾU; proto UNKNOWN (unsupported) vẫn
        # phải xuống Flow Tracker vì là bằng chứng port scan (REQ-28.4).
        missing_data = any(not reason.startswith("unsupported") for reason in reasons)
        if missing_data and self.config["missing_data_policy"] == "skip":
            pp["action"] = "skipped"
            return False
        pp["action"] = "marked"
        return True
