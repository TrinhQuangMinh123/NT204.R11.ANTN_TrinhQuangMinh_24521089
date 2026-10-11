"""CLI của bài tập 1: bắt/đọc packet -> parse -> ghi JSON Lines (design §5.5).

Đây là nơi DUY NHẤT nối dây giữa các tầng: chọn nguồn, dựng danh sách module
phía sau, đưa process_frame cho Runner. Mọi tầng còn lại không biết gì về
nhau, nên bài sau thêm một module chỉ phải sửa file này (NFR-9, ADR-12).

Thông báo và trợ giúp viết bằng tiếng Anh cho đồng nhất với phần argparse tự
in ra (usage/error) và với thông báo lỗi của hệ điều hành.
"""
import argparse
import os
import signal
import sys

from idps.capture import SourceError
from idps.capture.live import LiveSource
from idps.capture.pcap import PcapSource
from idps.core.runner import Runner
from idps.decode.pipeline import process_frame
from idps.output.jsonl import JsonlWriter
from idps.process.chain import ProcessingChain
from idps.process.config import Config, ConfigError
from idps.process.decoder import Decoder
from idps.process.flow import CLOSE_REASONS, FlowTracker
from idps.process.preprocessor import Preprocessor

PROG = "main.py"
DEFAULT_OUTPUT = "events.jsonl"
DEFAULT_FLOW_OUTPUT = "flows.jsonl"
DEFAULT_CONFIG = "idps-config.json"

EXIT_OK = 0
EXIT_ERROR = 1          # lỗi đầu vào / môi trường (design §5.5)
# Exit 2 do argparse tự trả khi cú pháp tham số sai — không tự đặt ở đây.


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Capture or read packets, parse them and write JSON Lines events.",
    )
    # required=True + nhóm loại trừ: truyền cả hai HOẶC không truyền cái nào
    # đều ra usage + exit 2 (REQ-3.3, C-2). Để argparse lo thay vì tự kiểm
    # bằng if, vì đó đúng là lỗi cú pháp tham số.
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--interface", metavar="IFACE", help="capture live on this interface")
    mode.add_argument("--pcap", metavar="FILE", help="read packets from a pcap file")
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        default=DEFAULT_OUTPUT,
        help=f"write events here (default: {DEFAULT_OUTPUT})",
    )
    # --- bài 2 (REQ-35, REQ-36) ---
    parser.add_argument(
        "--flow-output",
        metavar="FILE",
        default=DEFAULT_FLOW_OUTPUT,
        help=f"write flow records here (default: {DEFAULT_FLOW_OUTPUT})",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help=f"config file (default: {DEFAULT_CONFIG} if present, else built-in)",
    )
    # default=None chứ không [] để tránh bẫy của action="append" (cộng dồn vào
    # list mặc định); main() đổi None thành [].
    parser.add_argument(
        "--set",
        action="append",
        default=None,
        dest="overrides",
        metavar="KEY=VALUE",
        help="override one config parameter, repeatable (e.g. --set tcp.new=5)",
    )
    return parser


def build_chain(config, flow_sinks):
    """Chuỗi stage của bài 2 + tracker (để main đọc thống kê của nó).

    Thứ tự Decoder → Preprocessor → FlowTracker là C-17: Flow Tracker chỉ nhận event
    đã giải mã và chuẩn hoá. FlowTracker nhận `flow_sinks` — vòng đời của chúng
    thuộc tracker (nó xả flow còn lại rồi mới đóng chúng, ADR-25).
    """
    tracker = FlowTracker(config, flow_sinks)
    return ProcessingChain([Decoder(config), Preprocessor(config), tracker]), tracker


def build_sinks(args, chain) -> list:
    """Các module phía sau của lần chạy này, theo thứ tự nhận event (REQ-20.1).

    `ProcessingChain` đứng TRƯỚC bộ ghi event, nên event chỉ được ghi SAU khi đã
    đi qua các stage (ADR-17). Runner, JsonlWriter của bài 1 không đổi.
    """
    return [chain, JsonlWriter(args.output)]


def build_flow_sinks(args) -> list:
    """Kênh xuất flow record (ADR-25). Mở ở đây để lỗi ghi lộ ra TRƯỚC nguồn.

    Dùng lại chính JsonlWriter của bài 1: hợp đồng của nó là "một dict → một dòng
    JSON + flush", không đọc khoá nào của event, nên ghi flow record y nguyên.
    Danh sách này KHÔNG nằm trong `sinks` của Runner — nếu nằm, Runner sẽ gọi
    handle() với *event* và ghi sai schema vào flows.jsonl (ADR-25).
    """
    return [JsonlWriter(args.flow_output)]


def flow_stats_line(chain, tracker) -> str:
    """Dòng thống kê thứ hai (REQ-35.5, design §5.5), cùng kiểu `khoá=giá trị`.

    Chỉ in lý do đóng có xuất hiện, theo thứ tự cố định của Phụ lục H. Ba số lỗi là
    số ngoại lệ bất ngờ của từng stage — bộ dữ liệu hỏng vẫn phải ra 0 (NFR-10),
    vì lỗi dự kiến là dữ liệu chứ không phải ngoại lệ.
    """
    closed = tracker.closed_by_reason
    parts = [f"flows_created={tracker.flows_created}",
             f"flows_closed={sum(closed.values())}"]
    parts += [f"close.{reason}={closed[reason]}" for reason in CLOSE_REASONS if reason in closed]
    errors = chain.error_counts
    parts += [f"decode_errors={errors.get('decoder', 0)}",
              f"preprocess_errors={errors.get('preprocessor', 0)}",
              f"flow_errors={errors.get('flow', 0)}"]
    return " ".join(parts)


def parse_overrides(raw_list, parser):
    """Tách mỗi `--set KEY=VALUE` thành cặp (khoá, giá trị-chuỗi).

    Thiếu dấu `=` là lỗi CÚ PHÁP tham số dòng lệnh → `parser.error` in usage và
    exit 2, cùng lối argparse của bài 1 (design §5.4). Ngữ nghĩa (khoá lạ, sai
    kiểu) để Config lo → ConfigError → exit 1. partition giữ được `=` trong giá
    trị (vd một đường dẫn), chỉ tách ở dấu `=` đầu tiên.
    """
    pairs = []
    for raw in raw_list:
        key, sep, value = raw.partition("=")
        if not sep:
            parser.error(f"invalid --set, expected KEY=VALUE: {raw}")
        pairs.append((key, value))
    return pairs


def resolve_config_path(explicit):
    """`--config X` → X (Config lỗi nếu thiếu). Không có `--config` → tệp mặc định
    `idps-config.json` nếu tồn tại, ngược lại None (dùng mặc định Phụ lục J)."""
    if explicit is not None:
        return explicit
    return DEFAULT_CONFIG if os.path.exists(DEFAULT_CONFIG) else None


class _ConfigEchoSource:
    """Bọc nguồn để in dòng `config={…}` NGAY TRƯỚC frame đầu tiên (REQ-36.4).

    In đúng lúc đó, không sớm hơn: một nguồn hỏng mà lỗi chỉ lộ ra khi frames()
    chạy (vd thiếu CAP_NET_RAW — LiveSource mở socket lúc lặp, không lúc __init__)
    sẽ KHÔNG để lại dòng config lạc trên stdout. Nhờ vậy hành vi "stdout rỗng khi
    nguồn hỏng" của bài 1 giữ nguyên, và Runner không phải đổi một dòng (D11).

    Không đụng tới frame: chỉ quan sát "frame đầu tiên" để in một lần, rồi chuyển
    tiếp y nguyên mọi frame. Một lần chạy không có packet nào (PCAP rỗng) in đúng
    những gì bài 1 in — không có dòng config, vì không có "packet đầu tiên".
    """

    def __init__(self, source, config):
        self._source = source
        self._config = config

    def frames(self):
        printed = False
        for frame in self._source.frames():
            if not printed:
                print(self._config.line())
                printed = True
            yield frame


def build_source(args):
    """Chọn nguồn theo mode. Ném SourceError nếu nguồn không dùng được.

    Hai nguồn có cùng hợp đồng `frames() -> Iterator[RawFrame]` (design §6),
    nên đây là chỗ DUY NHẤT trong chương trình phân biệt live với pcap — mọi
    tầng sau nó xử lý một frame của lab y như một frame đọc từ file (REQ-3.2).
    """
    if args.pcap is not None:
        return PcapSource(args.pcap)
    return LiveSource(args.interface)


def on_sigterm(signum, frame):
    """SIGTERM -> KeyboardInterrupt, để dừng êm đi chung một đường (ADR-8).

    Ba lý do phải tự đăng ký thay vì để mặc định:

    1. Tiến trình chạy làm PID 1 của container (`docker compose up` gọi thẳng
       chương trình) KHÔNG có hành vi mặc định cho SIGTERM: kernel chỉ giao
       tín hiệu cho PID 1 nếu nó đã cài handler. Không cài thì `docker compose
       stop` gửi SIGTERM, đợi hết thời gian chờ rồi SIGKILL — mất dòng thống kê
       và mất luôn cơ hội đóng sink.
    2. Kể cả khi không phải PID 1 (`docker compose exec`), hành vi mặc định là
       chết ngay, không chạy `finally` nào.
    3. Ctrl+C (SIGINT) đã có sẵn đường đi này vì Python biến nó thành
       KeyboardInterrupt. Biến SIGTERM thành cùng một ngoại lệ thì chỉ có MỘT
       đường dừng phải test và phải giải thích, thay vì hai (REQ-1.6, 1.7).

    Ném ngoại lệ từ trong handler là cách duy nhất cắt được vòng lặp đang chờ
    trong `recv`: syscall bị ngắt, Python chạy handler rồi ném tại đúng chỗ
    đang chờ, nên `with` của LiveSource và `finally` của Runner đều chạy.
    """
    raise KeyboardInterrupt


def fail(message: str) -> int:
    print(f"{PROG}: {message}", file=sys.stderr)
    return EXIT_ERROR


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Đăng ký trước khi mở tài nguyên nào. Cửa sổ còn hở: SIGTERM đến đúng lúc
    # đang dựng sink/nguồn thì KeyboardInterrupt lọt ra khỏi main() -> exit
    # khác 0, nhưng lúc đó chưa có event nào được ghi nên không mất dữ liệu.
    signal.signal(signal.SIGTERM, on_sigterm)

    # --set sai cú pháp -> exit 2 (trước mọi tài nguyên). Config lỗi -> exit 1
    # TRƯỚC khi mở nguồn và trước packet đầu tiên (REQ-36.3).
    overrides = parse_overrides(args.overrides or [], parser)
    try:
        config = Config.load(resolve_config_path(args.config), overrides)
    except ConfigError as exc:
        return fail(str(exc))

    # Flow writer + sink TRƯỚC nguồn (REQ-13.4, 20.4, 35.7, §8.2): chạy live 10
    # phút rồi mới phát hiện không ghi được file là mất trắng. Bắt Exception chứ
    # không chỉ OSError vì module bài sau có thể mở tài nguyên khác.
    try:
        flow_sinks = build_flow_sinks(args)
    except Exception as exc:  # noqa: BLE001 - lỗi khởi động của module phía sau
        return fail(f"cannot open output: {exc}")
    chain, tracker = build_chain(config, flow_sinks)
    try:
        sinks = build_sinks(args, chain)
    except Exception as exc:  # noqa: BLE001
        for sink in flow_sinks:
            sink.close()
        return fail(f"cannot open output: {exc}")

    try:
        source = build_source(args)
    except SourceError as exc:
        # Sink đã mở ở trên -> phải tự đóng, vì chưa có Runner nào lo hộ. Đóng
        # chain cũng đóng flow_sinks (tracker.close, chưa có flow nào để xả).
        for sink in sinks:
            sink.close()
        return fail(str(exc))

    # _ConfigEchoSource in dòng config (REQ-36.4) ngay trước packet đầu tiên —
    # run.log tự giải thích được vì sao flow hết hạn (T12). Không in nếu nguồn
    # hỏng trước khi có frame nào (giữ hành vi stdout rỗng của bài 1).
    runner = Runner(_ConfigEchoSource(source, config), sinks, process_frame)
    try:
        stats = runner.run()
    except KeyboardInterrupt:
        # Dừng theo yêu cầu người dùng = kết thúc bình thường (REQ-1.6): sink
        # đã được Runner đóng trong finally, chỉ còn in thống kê rồi exit 0.
        stats = runner.stats
    except SourceError as exc:
        # Nguồn hỏng giữa chừng (vd global header cụt): Runner đã đóng sink.
        return fail(str(exc))

    # REQ-13.5 + REQ-20.3: in SAU khi mọi sink đã đóng — kể cả flow sink, do
    # tracker.close() xả flow còn lại rồi đóng chúng — nên con số trong các dòng
    # này luôn khớp với số dòng đã nằm trong file. Dòng bài 1 giữ nguyên từng ký tự.
    print(stats.line())
    print(flow_stats_line(chain, tracker))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
