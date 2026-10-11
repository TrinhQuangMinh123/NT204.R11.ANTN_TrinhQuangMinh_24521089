"""Flow/Connection Tracker — stage 3: gom packet hai chiều thành phiên (REQ-30–35).

Một *flow* là mọi packet của cùng một phiên, cả hai chiều. Detection Engine cần
đơn vị này vì dấu hiệu tấn công (SYN không được trả lời, tỉ lệ gửi/nhận) chỉ thấy
được khi gom nhiều packet lại.

File này đọc event từ khoá đã chuẩn hoá của Preprocessor và KHÔNG import gì ngoài
`.chain` — đối tượng thư viện không lọt sang tầng phát hiện (đề bài §6, I-20).
"""
from .chain import Stage

_PROTOCOLS = ("TCP", "UDP")

_ANY = None   # "bất kỳ trạng thái" trong bảng chuyển trạng thái


# --- máy trạng thái TCP (Phụ lục I.1) ---------------------------------------
# Dạng DỮ LIỆU: mỗi dòng (từ trạng thái, tên điều kiện, sang trạng thái); dòng đầu
# tiên khớp thắng, không khớp dòng nào thì giữ nguyên. Thứ tự dòng LÀ luật ưu tiên:
#   RST thắng tất cả · RESET/CLOSED "hút" mọi packet còn lại (FIN/ACK truyền lại
#   vẫn được đếm vào flow cũ, không đẻ flow mới — REQ-31.9) · CLOSING chỉ thành
#   CLOSED khi đã có FIN hai chiều và gặp ACK · FIN đầu tiên → CLOSING.
_TCP_TRANSITIONS = (
    (_ANY,        "rst",                "RESET"),
    ("RESET",     "always",             "RESET"),
    ("CLOSED",    "always",             "CLOSED"),
    ("CLOSING",   "ack_after_both_fin", "CLOSED"),
    (_ANY,        "fin",                "CLOSING"),
    ("HANDSHAKE", "final_ack",          "ESTABLISHED"),
)

# Điều kiện nhận (flow, cờ, chiều) và nhìn flow ở thời điểm TRƯỚC packet này —
# bookkeeping (chiều đã gửi FIN, đã thấy SYN/ACK) cập nhật SAU khi tra bảng.
# `ack_after_both_fin`: ACK đầu tiên SAU khi cả hai chiều đã FIN — không cần theo
# seq/ack vì việc đó chỉ có nghĩa khi ghép luồng TCP, ngoài phạm vi bài.
_TCP_CONDITIONS = {
    "always": lambda flow, flags, direction: True,
    "rst": lambda flow, flags, direction: "RST" in flags,
    "fin": lambda flow, flags, direction: "FIN" in flags,
    "ack_after_both_fin": lambda flow, flags, direction: (
        len(flow.fin_directions) == 2 and "ACK" in flags
    ),
    "final_ack": lambda flow, flags, direction: (
        flow.seen_synack and direction == "forward"
        and "ACK" in flags and "SYN" not in flags
    ),
}


class Flow:
    """Một phiên đang theo dõi. Mỗi task sau thêm field vào đây (state, counter…)."""

    def __init__(self, key, endpoint_a, endpoint_b):
        self.flow_id = None            # FlowTracker cấp ngay sau khi tạo (ADR-22)
        self.key = key
        self.protocol = key[0]
        self.endpoint_a = endpoint_a   # (ip, port) nguồn của packet ĐẦU TIÊN
        self.endpoint_b = endpoint_b
        self.state = None
        self.midstream = None          # TCP: True nếu packet đầu không phải SYN
        self.seen_synack = False       # đã thấy SYN+ACK chiều ngược trong HANDSHAKE
        self.fin_directions = set()    # chiều đã gửi FIN; chỉ đo kích thước, không in
        self.start_usec = None
        self.last_seen_usec = None

    def update(self, event, direction):
        """Tính packet này vào flow: trạng thái rồi mốc thời gian (design §6, bước 6).

        `last_seen` cập nhật cả với packet không có payload (ACK/SYN/FIN trơn —
        REQ-31.7): nếu bỏ qua, flow chỉ có handshake trông như im lặng.
        """
        ts = event["preprocess"].get("ts_usec")
        if self.start_usec is None:
            self.start_usec = ts
        self.last_seen_usec = ts
        if self.protocol == "TCP":
            self._step_tcp(event, direction)

    def _step_tcp(self, event, direction):
        flags = (event.get("tcp") or {}).get("flags") or []
        if self.state is None:
            # Packet đầu: chỉ SYN thuần mới là mở đầu bắt tay (31.1). Mọi packet
            # khác — kể cả SYN+ACK — là bắt giữa phiên, không phải lỗi (31.8).
            if "SYN" in flags and "ACK" not in flags:
                self.state, self.midstream = "HANDSHAKE", False
            else:
                self.state, self.midstream = "ESTABLISHED", True
        for source, condition, target in _TCP_TRANSITIONS:
            if source in (_ANY, self.state) and _TCP_CONDITIONS[condition](self, flags, direction):
                self.state = target
                break
        if "FIN" in flags:
            self.fin_directions.add(direction)
        if "SYN" in flags and "ACK" in flags and direction == "backward":
            self.seen_synack = True


def _endpoints(event):
    """((ip, port) nguồn, (ip, port) đích, protocol) hoặc lý do không đủ 5-tuple.

    Trả `(None, None, None, lý_do)` khi thiếu: REQ-30.7 — không đủ 5-tuple thì
    không tạo flow. IP lấy từ `preprocess` (đã bỏ số 0 vô nghĩa) để `010.020.0.010`
    và `10.20.0.10` không tách thành hai flow.
    """
    pre = event["preprocess"]
    protocol = pre.get("transport_proto")
    if protocol not in _PROTOCOLS:
        return None, None, None, f"no_five_tuple: transport_proto={protocol!r}"
    parts = (
        ("src_ip", pre.get("src_ip")), ("dst_ip", pre.get("dst_ip")),
        ("src_port", event.get("src_port")), ("dst_port", event.get("dst_port")),
    )
    for name, value in parts:
        if value is None:
            return None, None, None, f"no_five_tuple: missing {name}"
    src = (pre["src_ip"], event["src_port"])
    dst = (pre["dst_ip"], event["dst_port"])
    return src, dst, protocol, None


class FlowTable:
    """Bảng flow đang active: một `dict` theo khoá chuẩn hoá (ADR-23, phương án A).

    `dict` giữ thứ tự chèn nên thứ tự duyệt = thứ tự flow được tạo — nền cho
    output tất định (I-21). Không bao giờ sắp xếp lại bằng `set`.
    """

    def __init__(self):
        self._flows = {}

    @staticmethod
    def make_key(protocol, src, dst):
        """`(protocol, min(e1,e2), max(e1,e2))` — hai chiều cho CÙNG một khoá.

        Chỉ cần một thứ tự toàn phần bất kỳ (so tuple `(ip_str, port)`), không cần
        thứ tự có nghĩa: mục đích duy nhất là A→B và B→A rơi vào cùng một ô.
        """
        return (protocol, min(src, dst), max(src, dst))

    def __len__(self):
        return len(self._flows)

    def flows(self):
        """Các flow đang active, theo thứ tự được tạo (thứ tự chèn của dict)."""
        return list(self._flows.values())

    def get_or_create(self, key, event):
        """Trả `(flow, vừa_tạo)`. Flow mới lấy NGUỒN của event làm endpoint A."""
        flow = self._flows.get(key)
        if flow is not None:
            return flow, False
        src, dst, _, _ = _endpoints(event)
        flow = Flow(key, src, dst)
        self._flows[key] = flow
        return flow, True


class FlowTracker(Stage):
    """Gán mỗi event vào một flow, ghi `flow_id`/`direction` lên event.

    `flow_id` là bộ đếm riêng của tracker, tăng từ 1 (ADR-22): flow mới → số mới,
    nên 5-tuple quay lại sau khi flow cũ đóng tự có id khác (REQ-30.6), và hai
    tracker độc lập chạy cùng input cho cùng dãy id (NFR-11). Không dùng `hash()`
    của Python vì nó đổi theo từng tiến trình.
    """

    name = "flow"

    def __init__(self, config):
        self.config = config
        self.table = FlowTable()
        self._next_flow_id = 1

    def process(self, event):
        src, dst, protocol, problem = _endpoints(event)
        if problem:
            event["flow"]["flow_id"] = None
            event["flow"]["reasons"].append(problem)
            return True                    # vẫn đi tiếp: không đủ 5-tuple không phải lỗi

        key = FlowTable.make_key(protocol, src, dst)
        flow, created = self.table.get_or_create(key, event)
        if created:
            flow.flow_id = self._next_flow_id
            self._next_flow_id += 1

        event["flow"]["flow_id"] = flow.flow_id
        direction = "forward" if src == flow.endpoint_a else "backward"
        flow.update(event, direction)
        event["flow"]["direction"] = direction
        event["flow"]["state"] = flow.state     # trạng thái SAU khi tính packet này
        return True
