"""CLI của bài tập 1: bắt/đọc packet -> parse -> ghi JSON Lines (design §5.5).

Đây là nơi DUY NHẤT nối dây giữa các tầng: chọn nguồn, dựng danh sách module
phía sau, đưa process_frame cho Runner. Mọi tầng còn lại không biết gì về
nhau, nên bài sau thêm một module chỉ phải sửa file này (NFR-9, ADR-12).

Thông báo và trợ giúp viết bằng tiếng Anh cho đồng nhất với phần argparse tự
in ra (usage/error) và với thông báo lỗi của hệ điều hành.
"""
import argparse
import signal
import sys

from idps.capture import SourceError
from idps.capture.live import LiveSource
from idps.capture.pcap import PcapSource
from idps.core.runner import Runner
from idps.decode.pipeline import process_frame
from idps.output.jsonl import JsonlWriter

PROG = "main.py"
DEFAULT_OUTPUT = "events.jsonl"

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
    return parser


def build_sinks(args) -> list:
    """Các module phía sau của lần chạy này, theo thứ tự nhận event (REQ-20.1).

    Bài 1 chỉ có bộ ghi JSON Lines. Bài sau (đặc trưng, phát hiện, cảnh báo,
    chặn) nối thêm sink vào đúng danh sách này — không sửa capture/decode.
    """
    return [JsonlWriter(args.output)]


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
    args = build_parser().parse_args(argv)

    # Đăng ký trước khi mở tài nguyên nào. Cửa sổ còn hở: SIGTERM đến đúng lúc
    # đang dựng sink/nguồn thì KeyboardInterrupt lọt ra khỏi main() -> exit
    # khác 0, nhưng lúc đó chưa có event nào được ghi nên không mất dữ liệu.
    signal.signal(signal.SIGTERM, on_sigterm)

    # Sink TRƯỚC nguồn (REQ-13.4, 20.4, §8.2): chạy live 10 phút rồi mới phát
    # hiện không ghi được file là mất trắng. Bắt Exception chứ không chỉ
    # OSError vì module bài sau có thể mở tài nguyên khác (socket, database).
    try:
        sinks = build_sinks(args)
    except Exception as exc:  # noqa: BLE001 - lỗi khởi động của module phía sau
        return fail(f"cannot open output: {exc}")

    try:
        source = build_source(args)
    except SourceError as exc:
        # Sink đã mở ở trên -> phải tự đóng, vì chưa có Runner nào lo hộ.
        for sink in sinks:
            sink.close()
        return fail(str(exc))

    runner = Runner(source, sinks, process_frame)
    try:
        stats = runner.run()
    except KeyboardInterrupt:
        # Dừng theo yêu cầu người dùng = kết thúc bình thường (REQ-1.6): sink
        # đã được Runner đóng trong finally, chỉ còn in thống kê rồi exit 0.
        stats = runner.stats
    except SourceError as exc:
        # Nguồn hỏng giữa chừng (vd global header cụt): Runner đã đóng sink.
        return fail(str(exc))

    # REQ-13.5 + REQ-20.3: in SAU khi mọi sink đã đóng, nên con số trong dòng
    # này luôn khớp với số dòng đã nằm trong file.
    print(stats.line())
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
