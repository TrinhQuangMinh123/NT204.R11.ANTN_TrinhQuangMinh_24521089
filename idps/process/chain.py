"""Stage + ProcessingChain — cách gắn ba module bài 2 vào bài 1 (ADR-17).

Bài 1 có điểm gắn `EventSink` (REQ-20) nhưng `handle()` trả `None` -> một sink
KHÔNG chặn được event đi tiếp, trong khi REQ-26.4 đòi event `invalid` *không*
xuống Flow Tracker mà *vẫn* được ghi ra tệp (REQ-28.3). Nên bài 2 thêm một khái
niệm cạnh EventSink:

    EventSink.handle(event) -> None   : nơi event ĐI TỚI (điểm cuối, không chặn)
    Stage.process(event)   -> bool    : bước event ĐI QUA (False -> chặn phần sau)

Hai khái niệm vì có hai hợp đồng thật khác nhau, không phải vì thừa lớp. Chuỗi
sink của bài 2 dựng ở main.py là `[ProcessingChain([...]), JsonlWriter(events)]`,
nên Runner và JsonlWriter của bài 1 không đổi một dòng (D11, C-24).

File này chỉ import idps.core -> tầng process/ vẫn độc lập với capture/decode (I-20).
"""
from ..core.sink import EventSink


class Stage:
    """Một bước xử lý trung gian. Lớp con: Decoder, Preprocessor, FlowTracker.

    `name` là tên module dùng khi ghi lỗi (Phụ lục H: `decoder`/`preprocessor`/
    `flow`), để REQ-37.3 biết ngoại lệ đến từ đâu. `close()` rỗng vì phần lớn
    stage không giữ tài nguyên; FlowTracker ghi đè để xả flow còn lại (ADR-25).
    """

    name = "stage"

    def process(self, event: dict) -> bool:
        """Sửa event tại chỗ; trả True để đi tiếp, False để chặn các stage sau."""
        raise NotImplementedError

    def close(self) -> None:
        """Lần chạy kết thúc. ProcessingChain gọi cho MỌI stage trong finally."""


def _record_error(event: dict, stage: "Stage", exc: BaseException) -> None:
    """Ghi ngoại lệ bất ngờ của một stage vào `errors` của bài 1 (REQ-37.3, §4.2).

    Ghi vào `errors` (khoá bài 1) chứ không vào khoá mới: Phụ lục H nói tên module
    bài 2 nối tiếp quy ước lỗi của bài 1, nên có MỘT chỗ duy nhất đếm lỗi của cả
    hai bài, và `compute_status` của bài 1 tự biến status thành `malformed`.

    Phải phòng thủ để I-11 đúng với MỌI dict: một dict rác có `errors` không phải
    list vẫn không được làm hàm này ném — thay bằng list mới.
    """
    reason = f"{type(exc).__name__}: {exc}"
    name = getattr(stage, "name", "stage")
    errors = event.get("errors")
    if not isinstance(errors, list):
        errors = []
        event["errors"] = errors
    errors.append({"layer": name, "reason": reason})


class ProcessingChain(EventSink):
    """EventSink chứa danh sách Stage chạy tuần tự (ADR-17, phương án B).

    Thứ tự stage = thứ tự danh sách truyền vào -> C-17 nằm ở MỘT chỗ, đổi chỗ là
    đổi hành vi (có test). Vì LÀ một EventSink, nó gắn vào `sinks` của Runner bài
    1 mà Runner không cần biết tới `Stage`.
    """

    def __init__(self, stages):
        # Chụp lại danh sách để người gọi sửa list của họ sau đó không đổi hành vi.
        self.stages = list(stages)

    def handle(self, event: dict) -> None:
        """Chạy từng stage; dừng khi một stage trả False hoặc ném (I-11).

        `except Exception` quanh TỪNG stage là lưới cho bug của chính mình (ADR-4
        của bài 1): lỗi dự kiến là dữ liệu, nên số lỗi `decoder`/`preprocessor`/
        `flow` trên bộ dữ liệu hỏng phải bằng 0 — đó là cách NFR-10 đo được.
        Hàm này KHÔNG bao giờ ném: một packet lỗi không được làm sập cả lần chạy.
        """
        for stage in self.stages:
            try:
                keep = stage.process(event)
            except Exception as exc:  # noqa: BLE001 — lưới cho bug, không cho dữ liệu
                _record_error(event, stage, exc)
                return
            if not keep:
                return

    def close(self) -> None:
        """Đóng MỌI stage, kể cả khi một stage ném trong close().

        Bọc từng close() riêng: một stage ném không được chặn close() của stage
        còn lại (FlowTracker.close() phải chạy để xả flow còn trong bảng — ADR-25).
        KHÔNG để ngoại lệ lọt ra ngoài: ProcessingChain là sink đầu trong danh sách
        của Runner, nếu close() của nó ném thì Runner bỏ qua close() của JsonlWriter
        -> mất dòng cuối của tệp event. Lỗi lúc đóng là bug dọn dẹp, không phải dữ
        liệu, nên nuốt ở đây là lựa chọn đúng cho tính bền của lần chạy.
        """
        for stage in self.stages:
            try:
                stage.close()
            except Exception:  # noqa: BLE001 — bảo đảm stage còn lại vẫn được đóng
                pass
