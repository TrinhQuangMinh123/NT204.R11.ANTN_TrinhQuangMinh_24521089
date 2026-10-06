"""T0.4 — Stage + ProcessingChain: thứ tự, cổng chặn, bắt lỗi, close (ADR-17)."""
import random

from idps.core.event import new_event
from idps.core.frame import RawFrame
from idps.process.chain import ProcessingChain, Stage


def make_event(packet_id=1):
    frame = RawFrame(b"\x00" * 14, 1790486523, 0, 60, 1, "pcap")
    return new_event(frame, packet_id)


# --- stage giả -------------------------------------------------------------

class RecordingStage(Stage):
    """Ghi tên mình vào `log` khi chạy; trả `keep` cấu hình sẵn."""

    def __init__(self, name, log, keep=True):
        self.name = name
        self.log = log
        self._keep = keep

    def process(self, event):
        self.log.append(self.name)
        return self._keep


class RaisingStage(Stage):
    def __init__(self, name):
        self.name = name

    def process(self, event):
        raise RuntimeError("boom")


class KeyReaderStage(Stage):
    """Đọc một khoá -> ném KeyError trên dict thiếu khoá (dùng cho I-11)."""

    name = "reader"

    def process(self, event):
        return event["app_proto"] is None


class ClosingStage(Stage):
    def __init__(self, name, closed, raise_on_close=False):
        self.name = name
        self._closed = closed
        self._raise = raise_on_close

    def process(self, event):
        return True

    def close(self):
        self._closed.append(self.name)
        if self._raise:
            raise RuntimeError("close boom")


# --- thứ tự và cổng chặn ---------------------------------------------------

def test_runs_stages_in_list_order():
    log = []
    chain = ProcessingChain([
        RecordingStage("a", log), RecordingStage("b", log), RecordingStage("c", log),
    ])
    chain.handle(make_event())
    assert log == ["a", "b", "c"]


def test_false_stops_the_chain():
    log = []
    chain = ProcessingChain([
        RecordingStage("a", log, keep=False), RecordingStage("b", log),
    ])
    chain.handle(make_event())
    assert log == ["a"]  # b không được gọi


# --- bắt ngoại lệ (REQ-37.1–37.3) ------------------------------------------

def test_exception_recorded_and_stops_chain():
    log = []
    chain = ProcessingChain([
        RaisingStage("decoder"), RecordingStage("b", log),
    ])
    event = make_event()
    chain.handle(event)
    assert log == []  # stage sau không chạy
    assert len(event["errors"]) == 1
    err = event["errors"][0]
    assert err["layer"] == "decoder"
    assert err["reason"].startswith("RuntimeError: boom")


def test_exception_layer_is_stage_name():
    event = make_event()
    ProcessingChain([RaisingStage("flow")]).handle(event)
    assert event["errors"][0]["layer"] == "flow"


# --- I-11: không bao giờ ném ------------------------------------------------

def test_never_raises_on_empty_dict():
    ProcessingChain([KeyReaderStage()]).handle({})  # KeyError bên trong -> không lọt ra


def test_never_raises_on_garbage_dicts():
    rng = random.Random(1309)  # seed cố định -> ca lỗi tái lập được (lối I-1 bài 1)
    pool_keys = ["app_proto", "errors", "tcp", "src_port", "status", "x", "flow"]
    pool_vals = [None, 0, "", [], {}, 5, "UNKNOWN", b"x", 3.14]
    chain = ProcessingChain([KeyReaderStage()])
    for _ in range(200):
        n = rng.randint(0, len(pool_keys))
        garbage = {rng.choice(pool_keys): rng.choice(pool_vals) for _ in range(n)}
        chain.handle(garbage)  # không được ném với BẤT KỲ dict nào


def test_error_recorded_even_when_errors_key_is_wrong_type():
    """dict rác có `errors` không phải list vẫn không làm handle() ném (I-11)."""
    bad = {"errors": 5}
    ProcessingChain([RaisingStage("decoder")]).handle(bad)
    assert bad["errors"] == [{"layer": "decoder", "reason": "RuntimeError: boom"}]


# --- I-12: khoá vẫn đủ sau khi bị chặn -------------------------------------

def test_keys_after_gate(event_keys):
    """Event bị chặn giữa chuỗi vẫn đủ tập khoá schema v2 (I-12)."""
    log = []
    event = make_event()
    ProcessingChain([RecordingStage("a", log, keep=False), RecordingStage("b", log)]).handle(event)
    assert tuple(event) == event_keys
    assert event["flow"]["flow_id"] is None  # khoá flow còn nguyên dù dừng sớm


# --- I-15: chuỗi không đụng khoá bài 1 --------------------------------------

class WellBehavedStage(Stage):
    """Chỉ ghi vào ba khoá bài 2 — mô phỏng một stage đúng mực (I-15)."""

    name = "wellbehaved"

    def process(self, event):
        event["decode"]["status"] = "ok"
        event["preprocess"]["status"] = "valid"
        event["flow"]["flow_id"] = 1
        return True


def test_original_task1_keys_untouched():
    import copy
    event = make_event()
    before = copy.deepcopy({k: event[k] for k in event if k not in ("decode", "preprocess", "flow")})
    ProcessingChain([WellBehavedStage()]).handle(event)
    after = {k: event[k] for k in event if k not in ("decode", "preprocess", "flow")}
    assert after == before


# --- close() ---------------------------------------------------------------

def test_close_calls_every_stage():
    closed = []
    chain = ProcessingChain([ClosingStage("a", closed), ClosingStage("b", closed)])
    chain.close()
    assert closed == ["a", "b"]


def test_close_continues_when_a_stage_raises():
    """Một stage ném trong close() không chặn close() của stage còn lại."""
    closed = []
    chain = ProcessingChain([
        ClosingStage("a", closed, raise_on_close=True), ClosingStage("b", closed),
    ])
    chain.close()  # không ném ra ngoài
    assert closed == ["a", "b"]
