"""CLI của bài tập 1: bắt/đọc packet -> parse -> ghi JSON Lines (design §5.5).

Đây là nơi DUY NHẤT nối dây giữa các tầng: chọn nguồn, dựng danh sách module
phía sau, đưa process_frame cho Runner. Mọi tầng còn lại không biết gì về
nhau, nên bài sau thêm một module chỉ phải sửa file này (NFR-9, ADR-12).

Thông báo và trợ giúp viết bằng tiếng Anh cho đồng nhất với phần argparse tự
in ra (usage/error) và với thông báo lỗi của hệ điều hành.
"""
import argparse
import sys

from idps.capture import SourceError
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
    """Chọn nguồn theo mode. Ném SourceError nếu nguồn không dùng được."""
    if args.pcap is not None:
        return PcapSource(args.pcap)
    # T4.1/T4.2 thay dòng này bằng LiveSource(args.interface). Để nguyên một
    # lỗi rõ ràng thay vì bỏ trống: chạy --interface bây giờ phải nói được là
    # chưa có, chứ không im lặng ghi ra file rỗng.
    raise SourceError(f"live capture is not implemented yet: --interface {args.interface}")


def fail(message: str) -> int:
    print(f"{PROG}: {message}", file=sys.stderr)
    return EXIT_ERROR


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

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
