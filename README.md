# IDS/IPS — Hệ thống phát hiện và ngăn chặn xâm nhập

> **Repo:** https://github.com/TrinhQuangMinh123/NT204.R11.ANTN_TrinhQuangMinh_24521089
> **Lớp:** NT204.R11.ANTN · **Sinh viên:** Trịnh Quang Minh — 24521089

Đồ án tự xây dựng một IDS/IPS cơ bản, trong đó **từng chức năng được tự viết** thay vì dùng một engine
có sẵn (Snort/Suricata).

## 1. Mục tiêu

Nhu cầu cần đáp ứng: **học và hiểu IDS/IPS bằng cách tự lập trình từng thành phần** — bắt gói tin, bóc
tách giao thức, trích xuất đặc trưng, phát hiện tấn công và cảnh báo. Mục tiêu là hiểu cơ chế hoạt động,
không phải tạo ra một sản phẩm thương mại.

Ngoài phạm vi: machine learning, giao diện web, hiệu năng mức production, chống né tránh nâng cao.

## 2. Kiến trúc tổng quan

Toàn bộ hệ thống chạy bằng **Docker Compose**: các thành phần được đóng gói thành container và đặt trên
cùng một mạng ảo, gồm cảm biến IDS/IPS, máy mục tiêu và nguồn sinh traffic. Cách này cho phép tái hiện
lại từng kịch bản tấn công một cách lặp lại được và thu kết quả test trong môi trường cô lập.

Danh sách service, cấu hình mạng và công nghệ cụ thể của từng thành phần sẽ được bổ sung vào tài liệu
khi triển khai.

## 3. Chức năng dự kiến

| # | Task | Trạng thái |
|---|------|-----------|
| 1 | Thu thập packet | ☐ |
| 2 | Parser TCP, UDP | ☐ |
| 3 | Parser DNS, HTTP | ☐ |
| 4 | Trích xuất feature | ☐ |
| 5 | Phát hiện port scan | ☐ |
| 6 | Cảnh báo và ghi log | ☐ |
| 7 | Chức năng chặn (IPS) | ☐ |
| 8 | Test cases | ☐ |

## 4. Quy trình phát triển

- Mỗi task nhỏ, độc lập → **một commit riêng**, commit ngay khi xong.
- Mỗi test case → một commit riêng, kết quả lưu trong `TEST/`.
- Không gộp nhiều task/test case vào một commit; không sửa hay xoá lịch sử commit.
- Commit message ngắn, mô tả đúng việc đã làm: `Implement packet capture`, `Add port scan detection`,
  `Test port scan - case 01`.

## 5. Kiểm thử

Mỗi test case là một thư mục con trong `TEST/`, gồm mô tả kịch bản, cách tái hiện, dữ liệu đầu vào,
log/cảnh báo thu được và nhận xét kết quả.

## 6. Sử dụng công cụ AI

Công cụ: **Claude Opus 5**. Mục đích sử dụng:

- **Viết tài liệu** — soạn và chuẩn hoá `README.md`, ghi chú thiết kế, mô tả test case.
- **Lập kế hoạch** — chia đồ án thành các task nhỏ, độc lập và sắp xếp thứ tự thực hiện.
- **Thảo luận quan điểm và ý tưởng** — so sánh các hướng thiết kế để tự chọn hướng phù hợp.
- **Hỗ trợ debug** — giải thích traceback, chỉ ra nguyên nhân khi parser đọc sai byte hoặc luật phát
  hiện báo nhầm.
- **Giải thích kiến thức nền** — cấu trúc header, TCP handshake, hành vi của các kiểu quét cổng, để
  hiểu *tại sao* code cần viết như vậy.

**Cam kết:** AI đóng vai trò viết code, hỗ trợ tài liệu, và giải thích. Tôi tự viết lại mỗi file quan trọng, tự đọc hiểu và
có thể giải thích từng dòng mã nguồn trong repo này. Các tệp có sử dụng AI hỗ trợ được liệt kê bên dưới
và cập nhật trong suốt quá trình làm bài.

| Tệp | Mức độ hỗ trợ của AI |
|-----|----------------------|
| `README.md` | Soạn thảo nội dung tài liệu có giám sát|
| `Dockerfile` | AI viết bản đầu và giải thích từng dòng (base image, cache layer, biến môi trường); tôi đọc hiểu, build và kiểm tra |
| `requirements.txt` | AI tra phiên bản mới nhất và viết dòng pin; tôi kiểm tra phiên bản trong image khớp pin |
| `tests/test_layering.py` | AI viết bản đầu và giải thích cách dùng `ast` quét import (kể cả import tương đối); tôi đọc hiểu, chạy và thử chèn `import scapy` để thấy test fail |
| `compose.yaml` | AI viết bản đầu và giải thích bind mount, `user` theo UID host, `cap_drop`, `network_mode: none`; tôi đọc hiểu và chạy lại các lệnh kiểm tra (UID, CapEff, chủ sở hữu file). AI viết tiếp service `idps` (gateway) và hai mạng lab, giải thích vì sao sensor phải chạy root mới dùng được `NET_RAW`; tôi đọc hiểu và tự kiểm tra `ext0`/`int0`, `ip_forward`, địa chỉ IP |
| `lab/attacker/Dockerfile` | AI chọn base image cùng họ Debian với sensor và viết danh sách gói kèm lý do từng gói, giải thích `--no-install-recommends`; tôi đọc hiểu, build và tự kiểm tra route, ping |
| `lab/victim/Dockerfile` | AI chọn base image, viết danh sách gói, giải thích vì sao đổ log nginx ra stdout thay vì cấp thêm capability; tôi đọc hiểu, build và tự kiểm tra HTTP 200 trên cả hai port |
| `lab/victim/site.conf` | AI viết cấu hình hai port và `location /submit` để nhận POST, giải thích vì sao nginx trả 405 cho POST vào file tĩnh; tôi đọc hiểu và tự thử `curl -X POST` |
| `lab/victim/dnsmasq.conf` | AI viết cấu hình zone lab và giải thích `no-resolv`, `bind-interfaces`, vì sao phải đặt `local-ttl` khác 0 để TC-08 có giá trị; tôi đọc hiểu và tự kiểm bằng `dig` |
| `lab/victim/start.sh` | AI viết script khởi động ba dịch vụ và giải thích tiến trình nào giữ foreground, vì sao `exec nginx` làm PID 1, cờ `-n` của aiosmtpd; tôi đọc hiểu và tự kiểm bằng `nc` |
| `idps/core/frame.py` | AI viết dataclass `RawFrame` và giải thích vì sao `frozen=True`, vì sao mọi trường phải là kiểu dựng sẵn để object Scapy không lọt sang tầng decode; tôi đọc hiểu và tự thử gán lại trường để thấy `FrozenInstanceError` |
| `idps/decode/common.py` | AI viết `ParseResult`, `need()` và giải thích vì sao parser trả lỗi thay vì ném (ADR-4), vì sao `need()` phải chặn cả offset âm; tôi đọc hiểu và tự thử các ca biên |
| `tests/test_common.py` | AI viết test cho hợp đồng lõi và giải thích từng ca biên của `need()`; tôi đọc hiểu, chạy và tự thêm ca `need(b"", 0, 0)` |
| `idps/core/event.py` | AI viết khung event, `format_timestamp`, `b64`, `compute_status` và giải thích vì sao dựng đủ khoá ngay từ đầu, vì sao timestamp không đi qua `float`, vì sao `app_proto="UNKNOWN"` không làm status thành unknown; tôi đọc hiểu và tự đối chiếu thứ tự khoá với design §5.4 |
| `tests/test_event.py` | AI viết test cho tập khoá, timestamp, base64 và thứ tự ưu tiên status; tôi đọc hiểu, chạy và tự kiểm giá trị UTC bằng `date -u -d @<epoch>` |
| `idps/decode/ethernet.py` | AI viết parser Ethernet II và bảng tra `LINK_PARSERS`, giải thích vì sao dst MAC nằm trước src trên dây, vì sao `!` trong `struct` là bắt buộc, vì sao linktype lạ trả `None` chứ không phải `error`; tôi đọc hiểu và tự dựng frame bằng tay để kiểm |
| `tests/test_ethernet.py` | AI viết test cho frame hợp lệ, ARP, frame cụt mọi độ dài và linktype chưa hỗ trợ; tôi đọc hiểu, chạy và tự đối chiếu byte của frame với `tcpdump -xx` |
| `idps/decode/pipeline.py` | AI viết `process_frame` và giải thích vì sao tách `_decode` để `return` sớm, vì sao chỉ có MỘT `except Exception` và nó là lưới an toàn cho bug chứ không phải cách xử lý packet hỏng, vì sao `status` tính sau `except`; tôi đọc hiểu và tự lần theo từng nhánh của design §4.2 |
| `tests/test_pipeline.py` | AI viết test `test_never_raises` (500 chuỗi bytes ngẫu nhiên có seed cố định), các ca linktype lạ, ARP, frame cụt, bản ghi bị cắt và parser giả ném lỗi; tôi đọc hiểu, chạy và tự đổi seed để thấy test vẫn xanh |
| `conftest.py` | AI viết fixture `event_keys` và giải thích vì sao đặt `conftest.py` ở gốc repo thì `pytest` trần cũng import được `idps`; tôi đọc hiểu và tự chạy cả hai kiểu gọi pytest |
| `idps/capture/__init__.py` | AI thêm lớp `SourceError` và giải thích vì sao lỗi nguồn là ngoại lệ còn lỗi parse thì không (ADR-4), vì sao `__init__` không import `pcap.py`; tôi đọc hiểu |
| `idps/capture/pcap.py` | AI viết `PcapSource` và giải thích cấu trúc file PCAP (global header 24 byte, bản ghi 16 byte), vì sao phải tự đọc magic trước khi giao file cho Scapy, vì sao nano giây chia 1000 phải làm tròn xuống, vì sao `truncated` so `len(data)` với `caplen`; tôi đọc hiểu và tự soi file bằng `xxd` |
| `tests/test_capture.py` | AI viết test dựng file PCAP bằng `struct` cho các ca thứ tự, nano giây, big-endian, snaplen, bản ghi cụt, PCAPNG và file text; tôi đọc hiểu, chạy và tự sửa `incl_len` để thấy cờ `truncated` đổi theo |
| `idps/core/sink.py` | AI viết giao diện `EventSink` và giải thích vì sao điểm gắn module bài sau là một lớp cơ sở có `close()` rỗng, vì sao nó phải nằm trong `core/` (I-9); tôi đọc hiểu |
| `idps/output/jsonl.py` | AI viết `JsonlWriter` và giải thích vì sao chọn JSON Lines thay vì một mảng JSON, vì sao `flush()` từng dòng, vì sao `newline="\n"` và `ensure_ascii=True` là điều kiện để output tất định và không vỡ dòng; tôi đọc hiểu và tự thử nhét `\n` vào dữ liệu |
| `tests/test_jsonl.py` | AI viết test cho số dòng, thứ tự khoá, ca chèn `\n` vào URI, ca ghi ngay trước `close()` và các ca không mở được file; tôi đọc hiểu, chạy và tự kiểm file bằng `wc -l` |
| `idps/core/stats.py` | AI viết `Stats` và giải thích vì sao ba con số không chồng nhau (status chỉ nhận một giá trị), vì sao dòng thống kê để dạng `khoá=giá trị`; tôi đọc hiểu |
| `idps/core/runner.py` | AI viết `Runner` và giải thích vì sao vòng lặp chính chỉ viết một lần, vì sao `decode` phải TIÊM VÀO chứ không import (I-9: `core/` không được phụ thuộc `decode/`), vì sao `close()` nằm trong `finally` và `stats` là thuộc tính; tôi đọc hiểu và tự lần theo đường Ctrl+C |
| `tests/test_runner.py` | AI viết nguồn giả, sink giả và test cho `packet_id` 1..n, hai sink nhận cùng chuỗi event, `close()` khi `KeyboardInterrupt`, số đếm của `Stats`; tôi đọc hiểu, chạy và tự kiểm `git show --stat` không đụng `capture/`, `decode/` |
| `main.py` | AI viết CLI và giải thích vì sao nhóm `--interface`/`--pcap` để `argparse` kiểm (lỗi cú pháp → exit 2), vì sao dựng sink trước nguồn, vì sao `KeyboardInterrupt` là kết thúc bình thường (exit 0) còn `SourceError` là exit 1; tôi đọc hiểu và tự chạy từng ca exit code. AI nối tiếp chế độ `--interface` và handler SIGTERM, giải thích vì sao tiến trình làm PID 1 bỏ qua SIGTERM khi chưa cài handler và vì sao biến SIGTERM thành `KeyboardInterrupt` để chỉ còn một đường dừng; tôi đọc hiểu và tự kiểm `wc -l` tăng trong lúc đang bắt gói, gửi SIGTERM rồi xem exit code với dòng thống kê |
| `tests/test_cli.py` | AI viết test subprocess cho các ca hai mode/không mode, file không tồn tại, file text, PCAPNG, output không ghi được, output mặc định, dòng thống kê và bản ghi bị cắt; tôi đọc hiểu, chạy và tự đối chiếu `echo $?` |
| `tests/test_integration.py` | AI viết test tích hợp trên PCAP bắt thật từ lab và giải thích vì sao phải tự đếm bản ghi bằng `struct` thay vì dùng `PcapSource` (test không được lấy chính module đang kiểm làm thước đo), vì sao `test_deterministic` so từng byte; tôi đọc hiểu, chạy và tự bắt lại PCAP theo lệnh ghi trong docstring |
| `idps/capture/live.py` | AI viết `LiveSource` và giải thích vì sao lấy bytes qua socket `conf.L2listen` + `recv_raw()` thay vì `sniff()` (hợp đồng `frames()` là mô hình kéo, và `bytes(pkt)` là bytes Scapy dựng lại chứ không phải bytes trên dây — rủi ro R1), vì sao `/sys/class/net/<iface>/type` là ARPHRD chứ không phải LINKTYPE, vì sao sensor gateway không cần promiscuous, vì sao `PermissionError` phải đổi thành `SourceError`; tôi đọc hiểu và tự chạy lại trên `int0` trong lúc attacker ping, tự thử ca thiếu quyền trong `idps-offline` |
