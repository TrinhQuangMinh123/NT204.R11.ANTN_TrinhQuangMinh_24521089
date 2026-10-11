"""Flow/Connection Tracker — stage 3: gom packet hai chiều thành phiên (REQ-30–35).

Một *flow* là mọi packet của cùng một phiên, cả hai chiều. Detection Engine cần
đơn vị này vì dấu hiệu tấn công (SYN không được trả lời, tỉ lệ gửi/nhận) chỉ thấy
được khi gom nhiều packet lại.

File này đọc event từ khoá đã chuẩn hoá của Preprocessor và chỉ import module cùng
package `process/` — đối tượng thư viện không lọt sang tầng phát hiện (đề bài §6, I-20).
"""
import base64

from ..core.event import format_timestamp
from .chain import Stage
from .codecs import aggregate_status, mime_decode
from .reassembly import MailBuffer

_PROTOCOLS = ("TCP", "UDP")

_ANY = None   # "bất kỳ trạng thái" trong bảng chuyển trạng thái

# --- ngưỡng im lặng THEO TRẠNG THÁI (REQ-33.1, design §6) --------------------
# Tra bảng chứ không một con số chung: SYN chưa được trả lời (quét cổng) phải hết
# hạn sớm, phiên đã thiết lập thì được im lặng lâu hơn. (khoá cấu hình, close_reason)
_TCP_IDLE = {
    "HANDSHAKE":   ("tcp.new", "idle_new"),
    "ESTABLISHED": ("tcp.established", "idle_established"),
    "CLOSING":     ("tcp.established", "idle_established"),
    "CLOSED":      ("tcp.closed", "idle_closed"),
    "RESET":       ("tcp.closed", "idle_closed"),
}
_UDP_IDLE_ONE_WAY = ("udp.new", "idle_new")
_UDP_IDLE_BOTH_WAYS = ("udp.established", "idle_established")
_USEC_PER_SEC = 1_000_000

# Lỗi tầng nào của một packet cho thấy byte trong flow có thể đã mất (REQ-40.7):
# `truncated` của bài 1 cũng được ghi thành lỗi tầng `capture`.
_GAP_LAYERS = ("capture", "tcp")
_SMTP_DATA_ACCEPTED = 354

# Thứ tự cố định của close_reason (Phụ lục H) — để dòng thống kê tất định.
CLOSE_REASONS = ("idle_new", "idle_established", "idle_closed", "table_full", "end_of_run")

# Phiên bản schema của flow record — bộ đếm RIÊNG, không dùng chung với event (35.3).
FLOW_SCHEMA_VERSION = 1
_FLAG_COUNTERS = (("SYN", "syn_count"), ("ACK", "ack_count"),
                  ("FIN", "fin_count"), ("RST", "rst_count"))


def _iso(usec):
    """Số nguyên micro giây từ epoch → chuỗi ISO 8601 của bài 1 (ADR-7, không float)."""
    return format_timestamp(*divmod(usec, 1_000_000))


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
        self.packet_count = 0
        self.byte_count = 0
        self.direction_packets = {"forward": 0, "backward": 0}
        self.direction_bytes = {"forward": 0, "backward": 0}
        self.malformed_packets = 0
        self.payload_byte_count = 0
        self.flag_counts = {name: 0 for _, name in _FLAG_COUNTERS}
        self.application_protocol = None
        self.notes = []                # ghi chú mức flow, vào `reasons` của record
        # --- gom thư SMTP (REQ-40, ADR-26) — chỉ dùng khi flow là SMTP ---
        self.mails = []                # DecodedValue rule F8, vào `mails` của record
        self.pending_data = None       # chiều của lệnh DATA đang chờ reply 354
        self.mail_direction = None     # chiều gửi thư khi đang trong pha DATA
        self.mail_buffer = None        # MailBuffer; None = không ở trong pha DATA
        self.mail_bytes = 0            # tổng byte các thư đã gom: phần ngân sách đã dùng
        self.mail_gap = False          # đã thấy dấu hiệu mất byte trong pha DATA này
        self.mail_stopped = False      # chạm max_reassembly_bytes: không gom thêm thư nào
        self.close_reason = None       # FlowTable.expire / FlowTracker đặt lúc đóng

    def idle_rule(self):
        """(khoá cấu hình, close_reason) ứng với trạng thái hiện tại của flow.

        UDP luôn `ACTIVE`; thứ đổi ngưỡng là đã thấy chiều ngược hay chưa, nên tra
        theo `backward_packet_count` chứ không theo `state` (design §6).
        """
        if self.protocol == "TCP":
            return _TCP_IDLE[self.state]
        if self.direction_packets["backward"] == 0:
            return _UDP_IDLE_ONE_WAY
        return _UDP_IDLE_BOTH_WAYS

    def update(self, event, direction):
        """Tính packet này vào flow: trạng thái, counter rồi mốc thời gian (§6, bước 6).

        `last_seen` cập nhật cả với packet không có payload (ACK/SYN/FIN trơn —
        REQ-31.7): nếu bỏ qua, flow chỉ có handshake trông như im lặng.
        """
        ts = event["preprocess"].get("ts_usec")
        if self.start_usec is None:
            self.start_usec = ts
        # max(): PCAP dựng từ nhiều interface có thể có timestamp lùi; last_seen lùi
        # sẽ cho duration âm và làm flow trông hết hạn sớm hơn thực tế.
        if self.last_seen_usec is None or ts > self.last_seen_usec:
            self.last_seen_usec = ts
        if self.protocol == "TCP":
            self._step_tcp(event, direction)
        else:
            # UDP không có kết nối: MỘT trạng thái, không suy ra gì thêm (32.2, 32.4).
            self.state = "ACTIVE"
        self._account(event, direction)
        self._note_application_protocol(event)

    def _note_application_protocol(self, event):
        """Lấy từ packet ĐẦU TIÊN có app_proto thật, rồi giữ nguyên (34.6, A10).

        Không đổi về sau: nếu một packet giữa chừng bị nhận nhầm giao thức thì tên
        của cả phiên không được nhảy theo.
        """
        if self.application_protocol is None:
            proto = event["preprocess"].get("app_proto")
            if proto not in (None, "UNKNOWN"):
                self.application_protocol = proto

    def _account(self, event, direction):
        """Cộng packet vào counter toàn flow và theo chiều (REQ-34.3, 34.4, 34.7).

        `byte_count` là độ dài GỐC trên dây (`wire_len`), không phải số byte bắt
        được: capture cắt theo snaplen vẫn phải cho đúng khối lượng traffic.
        Thiếu `wire_len` thì dùng `cap_len` + ghi lý do, và packet VẪN được đếm
        (34.8). Packet bài 1 đánh dấu malformed vẫn đếm — nó là bằng chứng có
        traffic giữa hai endpoint (32.5).
        """
        size = event.get("wire_len")
        if size is None:
            size = event["cap_len"]
            event["flow"]["reasons"].append("wire_len_missing")
            if "wire_len_missing" not in self.notes:
                self.notes.append("wire_len_missing")
        self.packet_count += 1
        self.byte_count += size
        # Thống kê THÊM: byte tải của TCP/UDP, không thay byte_count (A13).
        payload = ((event.get("tcp") or event.get("udp") or {}).get("payload_len")) or 0
        self.payload_byte_count += payload
        if self.protocol == "TCP":
            # Đếm CỜ, không đếm vai trò: SYN+ACK cộng cả syn_count và ack_count (34.5).
            flags = (event.get("tcp") or {}).get("flags") or []
            for flag, name in _FLAG_COUNTERS:
                if flag in flags:
                    self.flag_counts[name] += 1
        self.direction_packets[direction] += 1
        self.direction_bytes[direction] += size
        if event.get("status") == "malformed":
            self.malformed_packets += 1
            event["flow"]["reasons"].append("malformed_packet")

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

    def to_record(self, close_usec, close_reason):
        """Dựng flow record: ĐÚNG tập khoá design §5.3, chỉ chứa kiểu JSON (I-13).

        Dựng từ giá trị đã chốt, không tham chiếu ngược event — record là bản chốt
        sổ của flow chứ không phải một event (C-18).
        """
        reasons = list(self.notes)
        if self.malformed_packets:
            reasons.append(f"malformed_packets={self.malformed_packets}")
        is_tcp = self.protocol == "TCP"
        return {
            "schema_version": FLOW_SCHEMA_VERSION,
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "endpoint_a": {"ip": self.endpoint_a[0], "port": self.endpoint_a[1]},
            "endpoint_b": {"ip": self.endpoint_b[0], "port": self.endpoint_b[1]},
            "start_time": _iso(self.start_usec),
            "last_seen": _iso(self.last_seen_usec),
            "close_time": _iso(close_usec),
            "start_time_usec": self.start_usec,
            "last_seen_usec": self.last_seen_usec,
            "duration_usec": self.last_seen_usec - self.start_usec,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward_packet_count": self.direction_packets["forward"],
            "forward_byte_count": self.direction_bytes["forward"],
            "backward_packet_count": self.direction_packets["backward"],
            "backward_byte_count": self.direction_bytes["backward"],
            "payload_byte_count": self.payload_byte_count,
            # Flow UDP: bốn counter cờ giữ 0 (không bao giờ được cộng — REQ-32.4).
            "syn_count": self.flag_counts["syn_count"],
            "ack_count": self.flag_counts["ack_count"],
            "fin_count": self.flag_counts["fin_count"],
            "rst_count": self.flag_counts["rst_count"],
            "state": self.state,
            "midstream": self.midstream if is_tcp else None,
            "close_reason": close_reason,
            "mails": self.mails,
            "reasons": reasons,
        }


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

    def __contains__(self, key):
        return key in self._flows

    def flows(self):
        """Các flow đang active, theo thứ tự được tạo (thứ tự chèn của dict)."""
        return list(self._flows.values())

    def expire(self, now_usec, config):
        """Flow đã im lặng QUÁ ngưỡng của trạng thái nó, theo thứ tự được tạo.

        Chỉ TRA, không xoá: tracker phải ghi flow record ra rồi mới `remove` (I-18).
        Đặt `flow.close_reason` vì lý do đóng phụ thuộc trạng thái LÚC hết hạn.
        Duyệt cả bảng mỗi packet: lab chỉ vài chục flow (A11, ADR-23 phương án A).
        """
        expired = []
        for flow in self._flows.values():
            key, reason = flow.idle_rule()
            if now_usec - flow.last_seen_usec > config[key] * _USEC_PER_SEC:
                flow.close_reason = reason
                expired.append(flow)
        return expired

    def evict_oldest(self):
        """Flow có `last_seen` cũ nhất (hoà → flow tạo trước), hoặc None nếu bảng rỗng."""
        if not self._flows:
            return None
        flow = min(self._flows.values(), key=lambda f: f.last_seen_usec)
        flow.close_reason = "table_full"
        return flow

    def remove(self, flow):
        del self._flows[flow.key]

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

    def __init__(self, config, flow_sinks=()):
        self.config = config
        self.flow_sinks = list(flow_sinks)   # nhận flow record (ADR-25), không nhận event
        self.table = FlowTable()
        self._next_flow_id = 1
        self.clock_usec = 0                  # "bây giờ" = timestamp packet, đơn điệu tăng
        self.closed_by_reason = {}           # close_reason -> số flow (dòng thống kê)

    def process(self, event):
        src, dst, protocol, problem = _endpoints(event)
        if problem:
            event["flow"]["flow_id"] = None
            event["flow"]["reasons"].append(problem)
            return True                    # vẫn đi tiếp: không đủ 5-tuple không phải lỗi

        key = FlowTable.make_key(protocol, src, dst)
        self._advance_clock(event)
        # Hết hạn TRƯỚC khi gán packet (REQ-33.6): packet đến sau timeout mở flow mới.
        for expired in self.table.expire(self.clock_usec, self.config):
            self._close(expired, expired.close_reason)
        if key not in self.table:
            while len(self.table) >= self.config["max_active_flows"]:
                self._close(self.table.evict_oldest(), "table_full")
        flow, created = self.table.get_or_create(key, event)
        if created:
            flow.flow_id = self._next_flow_id
            self._next_flow_id += 1

        event["flow"]["flow_id"] = flow.flow_id
        direction = "forward" if src == flow.endpoint_a else "backward"
        flow.update(event, direction)
        event["flow"]["direction"] = direction
        event["flow"]["state"] = flow.state     # trạng thái SAU khi tính packet này
        self._observe_mail(flow, event, direction)
        return True

    @property
    def flows_created(self):
        """Số flow đã tạo = flow_id lớn nhất đã cấp (ADR-22), nên tự đối chiếu được."""
        return self._next_flow_id - 1

    def _advance_clock(self, event):
        """`now = max(now, ts)`: lấy từ packet, không từ giờ hệ thống (REQ-33.2).

        Replay PCAP cũ vẫn hết hạn đúng, và kết quả không phụ thuộc tốc độ máy. Giữ
        đơn điệu để một packet có timestamp lùi không làm mọi flow "trẻ lại" (§4.3).
        """
        ts = event["preprocess"].get("ts_usec")
        if ts is not None and ts > self.clock_usec:
            self.clock_usec = ts

    def _close(self, flow, reason):
        """Chốt sổ flow: ghi record tới MỌI sink rồi mới cho rời bảng (I-18).

        Hết hạn là lúc *sinh ra* bằng chứng, không phải lúc xoá nó (REQ-33.1b).
        """
        self._finish_mail(flow)
        record = flow.to_record(self.clock_usec, reason)
        self.closed_by_reason[reason] = self.closed_by_reason.get(reason, 0) + 1
        for sink in self.flow_sinks:
            sink.handle(record)
        self.table.remove(flow)

    def close(self):
        """Hết lần chạy: xả MỌI flow còn lại (end_of_run) rồi mới đóng các sink.

        Đảo thứ tự thì sink đã đóng khi record cuối được gửi → mất bằng chứng.
        """
        for flow in self.table.flows():
            self._close(flow, "end_of_run")
        for sink in self.flow_sinks:
            sink.close()

    # --- gom thư SMTP ở mức flow (REQ-40, ADR-26) --------------------------

    def _observe_mail(self, flow, event, direction):
        if flow.mail_buffer is None:
            self._look_for_data_phase(flow, event, direction)
        elif direction == flow.mail_direction:
            self._collect_mail(flow, event)

    def _look_for_data_phase(self, flow, event, direction):
        """Vào pha DATA khi thấy lệnh `DATA` rồi reply `354` từ chiều NGƯỢC (ADR-26).

        Cần cả hai: lệnh `DATA` mới chỉ là lời xin, server từ chối (503…) thì sau
        đó không có thư nào. Lệnh khác của cùng bên gửi huỷ lời xin đang chờ.
        """
        if flow.mail_stopped or event["preprocess"].get("app_proto") != "SMTP":
            return
        app = event.get("app") or {}
        if app.get("kind") == "command":
            flow.pending_data = direction if app.get("command") == "DATA" else None
        elif (app.get("kind") == "response" and flow.pending_data is not None
              and direction != flow.pending_data
              and app.get("status_code") == _SMTP_DATA_ACCEPTED):
            self._enter_data_phase(flow, flow.pending_data)

    def _enter_data_phase(self, flow, mail_direction):
        flow.pending_data = None
        limit = self.config["max_reassembly_bytes"]
        # Ngân sách là của CẢ flow: các thư đã gom trước đó đã ăn một phần (REQ-40.4).
        room = limit - flow.mail_bytes
        if room <= 0:
            flow.mail_stopped = True
            self._note(flow, f"reassembly_limit={limit}")
            return
        flow.mail_buffer = MailBuffer(room)
        flow.mail_direction = mail_direction
        flow.mail_gap = False

    def _collect_mail(self, flow, event):
        """Nối payload (đọc từ `tcp.payload_b64`, không từ `app`) vào bộ đệm của flow.

        Parser SMTP của bài 1 không parse nội dung thư, nên bộ đệm không được phụ
        thuộc việc packet này có được nhận là SMTP hay không.
        """
        if any(error["layer"] in _GAP_LAYERS for error in event["errors"]):
            flow.mail_gap = True
        payload = base64.b64decode(((event.get("tcp") or {}).get("payload_b64")) or "")
        if not payload:
            return
        buffer = flow.mail_buffer
        complete = buffer.feed(payload)
        for raw in complete:
            self._add_mail(flow, raw, partial=False, reasons=())
        if buffer.stopped:
            # Dừng gom nhưng KHÔNG bỏ phần đã có: giải mã nó, đánh dấu dở dang (REQ-40.4).
            for raw in buffer.flush():
                self._add_mail(flow, raw, partial=True, reasons=buffer.reasons)
            flow.mail_stopped = True
            for reason in buffer.reasons:
                self._note(flow, reason)
            self._leave_data_phase(flow)
        elif complete:
            self._leave_data_phase(flow)     # dấu kết thúc đóng pha; thư sau mở bộ đệm mới

    def _finish_mail(self, flow):
        """Flow rời bảng khi bộ đệm còn dữ liệu → giải mã phần đã gom (REQ-40.3, 40.6)."""
        if flow.mail_buffer is None:
            return
        for raw in flow.mail_buffer.flush():
            self._add_mail(flow, raw, partial=True, reasons=("no_end_of_data_marker",))
        self._leave_data_phase(flow)

    def _leave_data_phase(self, flow):
        flow.mail_buffer = None              # giải phóng bộ nhớ ngay (REQ-40.6)
        flow.mail_direction = None
        flow.mail_gap = False

    def _add_mail(self, flow, raw, partial, reasons):
        """Giải mã một thư bằng CHÍNH `mime_decode` của REQ-23 (REQ-40.8), rule F8.

        `mail_bytes` cộng độ dài thư thô: là cận trên của kích thước đã giải mã
        (Base64/QP chỉ làm nhỏ đi) nên ngân sách không bao giờ bị tính hụt.
        """
        flow.mail_bytes += len(raw)
        result = mime_decode(raw, self.config["max_decode_bytes"])
        result["rule"] = "F8"
        result["reasons"] += list(reasons)
        if flow.mail_gap:
            partial = True
            result["reasons"].append("payload_gap")
            self._note(flow, "payload_gap")
        if partial:
            result["status"] = aggregate_status([result["status"], "partial"])
        flow.mails.append(result)

    @staticmethod
    def _note(flow, reason):
        if reason not in flow.notes:
            flow.notes.append(reason)
