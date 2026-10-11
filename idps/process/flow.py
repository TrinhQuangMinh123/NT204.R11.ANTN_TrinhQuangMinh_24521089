"""Flow/Connection Tracker — stage 3: gom packet hai chiều thành phiên (REQ-30–35).

Một *flow* là mọi packet của cùng một phiên, cả hai chiều. Detection Engine cần
đơn vị này vì dấu hiệu tấn công (SYN không được trả lời, tỉ lệ gửi/nhận) chỉ thấy
được khi gom nhiều packet lại.

File này đọc event từ khoá đã chuẩn hoá của Preprocessor và KHÔNG import gì ngoài
`.chain` — đối tượng thư viện không lọt sang tầng phát hiện (đề bài §6, I-20).
"""
from .chain import Stage

_PROTOCOLS = ("TCP", "UDP")


class Flow:
    """Một phiên đang theo dõi. Mỗi task sau thêm field vào đây (state, counter…)."""

    def __init__(self, key, endpoint_a, endpoint_b):
        self.flow_id = None            # FlowTracker cấp ngay sau khi tạo (ADR-22)
        self.key = key
        self.protocol = key[0]
        self.endpoint_a = endpoint_a   # (ip, port) nguồn của packet ĐẦU TIÊN
        self.endpoint_b = endpoint_b


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
        event["flow"]["direction"] = "forward" if src == flow.endpoint_a else "backward"
        return True
