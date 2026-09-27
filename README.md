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
| `idps/decode/pipeline.py` | AI viết `process_frame` và giải thích vì sao tách `_decode` để `return` sớm, vì sao chỉ có MỘT `except Exception` và nó là lưới an toàn cho bug chứ không phải cách xử lý packet hỏng, vì sao `status` tính sau `except`; tôi đọc hiểu và tự lần theo từng nhánh của design §4.2 AI nối tiếp tầng network/transport: bảng tra `TRANSPORT_PARSERS` theo protocol number, giải thích vì sao `src_ip`/`dst_ip` được lấy RA khỏi khoá `ipv4` (không ghi trùng một giá trị hai lần), vì sao mảnh IPv4 có `fragment_offset` khác 0 phải DỪNG chứ không parse transport (sẽ ra port và cờ bịa ra từ dữ liệu), vì sao `transport_proto` gán TRƯỚC khi parse; tôi đọc hiểu và tự lần theo design §4.2 | AI nối tiếp tầng ứng dụng (T6.4) và giải thích vì sao nhận diện và parse là hai bước tách rời (event có thể vừa biết là HTTP vừa báo lỗi ở header thứ 5), vì sao `app_proto="UNKNOWN"` không làm `status` thành `unknown`, vì sao pipeline lấy hàm parse qua registry của detector chứ không giữ bảng riêng; tôi đọc hiểu và tự chạy lại các ca port 80 / 8081 / payload lạ
| `tests/test_pipeline.py` | AI viết test `test_never_raises` (500 chuỗi bytes ngẫu nhiên có seed cố định), các ca linktype lạ, ARP, frame cụt, bản ghi bị cắt và parser giả ném lỗi; tôi đọc hiểu, chạy và tự đổi seed để thấy test vẫn xanh AI thêm các ca của T5.4 (5-tuple đầy đủ, ICMP → `UNKNOWN`, IPv4 cụt, IHL=3, `total_length` khai dài, mảnh đầu so với mảnh thứ hai, lỗi tầng `tcp`/`udp`, padding Ethernet) và hàm dựng packet ba tầng; tôi đọc hiểu, chạy và tự kiểm `test_never_raises` vẫn xanh AI thêm các ca của T6.4 (HTTP port 80 hai chiều, HTTP port 8081, payload rỗng, payload lạ vẫn `status="ok"`, header hỏng → `layer="http"`, DNS/UDP chưa hỗ trợ, mảnh và ICMP không tới detector) và ca ngẫu nhiên kiểm `app_proto` luôn nhất quán với `app`; tôi đọc hiểu, chạy và tự đổi port để thấy `detect_method` đổi theo |
| `conftest.py` | AI viết fixture `event_keys` và giải thích vì sao đặt `conftest.py` ở gốc repo thì `pytest` trần cũng import được `idps`; tôi đọc hiểu và tự chạy cả hai kiểu gọi pytest |
| `idps/capture/__init__.py` | AI thêm lớp `SourceError` và giải thích vì sao lỗi nguồn là ngoại lệ còn lỗi parse thì không (ADR-4), vì sao `__init__` không import `pcap.py`; tôi đọc hiểu |
| `idps/capture/pcap.py` | AI viết `PcapSource` và giải thích cấu trúc file PCAP (global header 24 byte, bản ghi 16 byte), vì sao phải tự đọc magic trước khi giao file cho Scapy, vì sao nano giây chia 1000 phải làm tròn xuống, vì sao `truncated` so `len(data)` với `caplen`; tôi đọc hiểu và tự soi file bằng `xxd` |
| `tests/test_capture.py` | AI viết test dựng file PCAP bằng `struct` cho các ca thứ tự, nano giây, big-endian, snaplen, bản ghi cụt, PCAPNG và file text; tôi đọc hiểu, chạy và tự sửa `incl_len` để thấy cờ `truncated` đổi theo |
| `idps/core/sink.py` | AI viết giao diện `EventSink` và giải thích vì sao điểm gắn module bài sau là một lớp cơ sở có `close()` rỗng, vì sao nó phải nằm trong `core/` (I-9); tôi đọc hiểu |
| `idps/output/jsonl.py` | AI viết `JsonlWriter` và giải thích vì sao chọn JSON Lines thay vì một mảng JSON, vì sao `flush()` từng dòng, vì sao `newline="\n"` và `ensure_ascii=True` là điều kiện để output tất định và không vỡ dòng; tôi đọc hiểu và tự thử nhét `\n` vào dữ liệu |
| `tests/test_jsonl.py` | AI viết test cho số dòng, thứ tự khoá, ca chèn `\n` vào URI, ca ghi ngay trước `close()` và các ca không mở được file; tôi đọc hiểu, chạy và tự kiểm file bằng `wc -l` |
| `idps/core/stats.py` | AI viết `Stats` và giải thích vì sao ba con số không chồng nhau (status chỉ nhận một giá trị), vì sao dòng thống kê để dạng `khoá=giá trị`; tôi đọc hiểu |
| `idps/core/runner.py` | AI viết `Runner` và giải thích vì sao vòng lặp chính chỉ viết một lần, vì sao `decode` phải TIÊM VÀO chứ không import (I-9: `core/` không được phụ thuộc `decode/`), vì sao `close()` nằm trong `finally` và `stats` là thuộc tính; tôi đọc hiểu và tự lần theo đường Ctrl+C |
| `tests/test_runner.py` | AI viết nguồn giả, sink giả và test cho `packet_id` 1..n, hai sink nhận cùng chuỗi event, `close()` khi `KeyboardInterrupt`, số đếm của `Stats`; tôi đọc hiểu, chạy và tự kiểm `git show --stat` không đụng `capture/`, `decode/` AI đổi frame `good` thành packet ba tầng hợp lệ cùng lý do như `tests/test_cli.py`; tôi đọc hiểu và tự chạy lại |
| `main.py` | AI viết CLI và giải thích vì sao nhóm `--interface`/`--pcap` để `argparse` kiểm (lỗi cú pháp → exit 2), vì sao dựng sink trước nguồn, vì sao `KeyboardInterrupt` là kết thúc bình thường (exit 0) còn `SourceError` là exit 1; tôi đọc hiểu và tự chạy từng ca exit code. AI nối tiếp chế độ `--interface` và handler SIGTERM, giải thích vì sao tiến trình làm PID 1 bỏ qua SIGTERM khi chưa cài handler và vì sao biến SIGTERM thành `KeyboardInterrupt` để chỉ còn một đường dừng; tôi đọc hiểu và tự kiểm `wc -l` tăng trong lúc đang bắt gói, gửi SIGTERM rồi xem exit code với dòng thống kê |
| `tests/test_cli.py` | AI viết test subprocess cho các ca hai mode/không mode, file không tồn tại, file text, PCAPNG, output không ghi được, output mặc định, dòng thống kê và bản ghi bị cắt; tôi đọc hiểu, chạy và tự đối chiếu `echo $?`. AI thêm các ca của chế độ live (interface không tồn tại, tên interface có `/`, thiếu `CAP_NET_RAW`) và giải thích vì sao ca thiếu quyền phải bắt trên `lo` và vì sao nó `skipif` khi chạy bằng root; tôi đọc hiểu, chạy trong `idps-offline` và tự thử lại bằng tay AI đổi `IPV4_STUB` thành packet Ethernet/IPv4/TCP hợp lệ thật khi T5.4 nối tầng network vào (hai byte `\x45\x00` cũ giờ là header IPv4 cụt → status đổi từ `ok` sang `malformed`) và giải thích vì sao phải sửa test thay vì sửa parser; tôi đọc hiểu và tự chạy lại các ca đếm status |
| `tests/test_integration.py` | AI viết test tích hợp trên PCAP bắt thật từ lab và giải thích vì sao phải tự đếm bản ghi bằng `struct` thay vì dùng `PcapSource` (test không được lấy chính module đang kiểm làm thước đo), vì sao `test_deterministic` so từng byte; tôi đọc hiểu, chạy và tự bắt lại PCAP theo lệnh ghi trong docstring |
| `idps/capture/live.py` | AI viết `LiveSource` và giải thích vì sao lấy bytes qua socket `conf.L2listen` + `recv_raw()` thay vì `sniff()` (hợp đồng `frames()` là mô hình kéo, và `bytes(pkt)` là bytes Scapy dựng lại chứ không phải bytes trên dây — rủi ro R1), vì sao `/sys/class/net/<iface>/type` là ARPHRD chứ không phải LINKTYPE, vì sao sensor gateway không cần promiscuous, vì sao `PermissionError` phải đổi thành `SourceError`; tôi đọc hiểu và tự chạy lại trên `int0` trong lúc attacker ping, tự thử ca thiếu quyền trong `idps-offline` |
| `idps/decode/ipv4.py` | AI viết parser IPv4 và giải thích vì sao IHL và `total_length` đều phải kiểm trước khi dùng làm chỉ số, vì sao payload cắt theo `total_length` (Ethernet đệm frame ngắn lên 60 byte), vì sao `is_fragment` xét cả MF lẫn offset để không bỏ sót mảnh đầu và mảnh cuối, vì sao cố tình KHÔNG kiểm header checksum (TX checksum offload làm packet bắt trên máy gửi có checksum sai); tôi đọc hiểu và tự dựng packet bằng tay để đối chiếu từng byte |
| `tests/test_ipv4.py` | AI viết hàm dựng packet IPv4 bằng `struct` và test cho IHL=6 có options, IHL=3, dữ liệu 19 byte, `total_length` khai dài hơn dữ liệu, padding Ethernet và ba ca mảnh (đầu, giữa, cuối); tôi đọc hiểu, chạy và tự sửa `total_length` để thấy test đổi màu |
| `idps/decode/tcp.py` | AI viết parser TCP và giải thích vì sao `data_offset` phải kiểm cả hai biên (`< 5` và vượt độ dài segment), vì sao cờ ghi thành danh sách tên theo thứ tự bit thay vì một con số hay một set (tất định + ba bước handshake phân biệt được), vì sao `next_proto` để `None` (port chỉ là gợi ý, ADR-5); tôi đọc hiểu và tự đối chiếu cờ với `tcpdump -S` |
| `tests/test_tcp.py` | AI viết test cho handshake SYN/SYN-ACK/ACK, từng cờ riêng lẻ, NULL và Xmas scan, `data_offset` 2 / 15 / 6-trên-segment-20-byte và round-trip base64 trên cả 256 giá trị byte; tôi đọc hiểu, chạy và tự thêm ca bit reserved để thấy nó không lẫn vào danh sách cờ |
| `idps/decode/udp.py` | AI viết parser UDP và giải thích vì sao `length` tính cả 8 byte header, vì sao phải so BẰNG với dữ liệu thật chứ không chỉ so lớn hơn (IPv4 đã cắt theo `total_length` nên byte dư là dấu hiệu packet dựng tay), vì sao checksum UDP trên IPv4 là tuỳ chọn nên không kiểm được; tôi đọc hiểu và tự sửa `length` để thấy lỗi đổi theo |
| `tests/test_udp.py` | AI viết test cho datagram DNS query thật, datagram chỉ có header, `length` = 6 / dài hơn / ngắn hơn dữ liệu, ca quét mọi `length` từ 0..39 để chứng minh chỉ một giá trị được nhận, và round-trip base64; tôi đọc hiểu, chạy và tự đối chiếu byte của DNS query với `dig` |
| `TEST/TC-01_tcp-handshake/README.md` | AI soạn mô tả test case (cách ghi lại, bảng 10 packet, giải thích vì sao `data_offset` 10 và 8 chứng minh được REQ-5.3); tôi tự chạy lại lệnh bắt gói, đối chiếu bảng với `tcpdump -n -r` và kiểm MAC đích là MAC của sensor |
| `idps/decode/detector.py` | AI viết registry `AppProto`, `detect()` và `matches_http`, giải thích vì sao TCP/UDP không có trường nào chỉ ra giao thức tầng trên nên phải nhận diện bằng chữ ký payload, vì sao port chỉ quyết định *thứ tự thử* chứ không quyết định *kết quả* (ADR-5), vì sao dấu cách sau method là phần bắt buộc của chữ ký, vì sao chia ứng viên thành hai nhóm thay vì `sorted`; tôi đọc hiểu và tự thử đổi port của registry để thấy `detect_method` đổi theo. AI thêm DNS vào registry (T8.2) và giải thích vì sao DNS là giao thức duy nhất không có chuỗi mở đầu để so (2 byte đầu là transaction ID, cả 65536 giá trị đều hợp lệ) nên nhận diện nó = **thử parse phần question**, và vì sao phần byte-level đó gọi sang `dns.question_section_fits()` chứ không viết lại trong detector; tôi đọc hiểu và tự kiểm `git show --stat` của commit không đụng `http.py` |
| `tests/test_detector.py` | AI viết test cho port 80 hai chiều, cả 6 method của REQ-10.3, port 8081/4444 (REQ-11.1), payload nhị phân / banner SSH / TLS trên port 80, payload rỗng, `GETX`, `get` chữ thường, chữ ký HTTP/2, chữ ký HTTP trên UDP và các bất biến của registry; tôi đọc hiểu, chạy và tự thêm payload mới để thấy nhóm nào bắt được. AI thêm các ca DNS của T8.2 (port 53 hai chiều, port 5353, 11 byte, QDCOUNT=0, question bị cắt, cùng bytes đó trên TCP, và một ca hồi quy chứng minh thêm DNS không đổi kết quả của HTTP); tôi đọc hiểu, chạy và tự dựng message DNS bằng hex |
| `idps/decode/http.py` | AI viết parser HTTP/1.x và giải thích vì sao mọi lỗi của giao thức văn bản là lỗi "tìm dấu phân cách", vì sao chỉ nhận CRLF chứ không nhận LF trần (dễ tính khác server = điều kiện của request smuggling), vì sao tên header giữ nguyên văn còn giá trị bị cắt OWS, vì sao `body_len` đếm byte có thật chứ không đọc `Content-Length`, vì sao không dùng `str.isdigit()` cho status code; tôi đọc hiểu và tự dựng request bằng `printf` \| `nc` để đối chiếu |
| `tests/test_http.py` | AI viết test cho request curl thật và response nginx thật, header trùng tên, OWS trong giá trị, POST có body và round-trip base64 trên 256 giá trị byte, ba mức chưa hoàn chỉnh (thiếu dòng trống / chỉ có request line / chưa trọn một dòng), LF trần, byte không ASCII ở header và ở body, status code `2x0` và chữ số Ả Rập, khoảng trắng trước dấu hai chấm, dòng nối obs-fold; tôi đọc hiểu, chạy và tự cắt payload ở các vị trí khác nhau để thấy cờ `incomplete` đổi theo |
| `TEST/TC-02_tcp-data/README.md` | AI soạn mô tả test case (chọn request 2000 byte để ba con số `total_length`/`data_offset`/`payload_len` phải khớp bằng phép tính, giải thích vì sao `total_length` 2138 > MTU 1500 vẫn đúng — bắt trên máy gửi, trước khi kernel chia segment); tôi tự chạy lại lệnh bắt gói, tự kiểm phép tính và đối chiếu `seq`/`ack` của bên kia |
| `TEST/TC-04_http-get/README.md` | AI soạn mô tả test case (chọn URI có `../../etc/passwd` trong query để chứng minh URI giữ nguyên văn, hai header cùng tên để chứng minh `headers` là list cặp; giải thích vì sao `curl` tự chuẩn hoá dot-segment ở path nên phải đặt sau `?`); tôi tự chạy lại lệnh, tự đối chiếu 132 byte payload với 5 cặp header trong event |
| `TEST/TC-05_http-post/README.md` | AI soạn mô tả test case (chọn body chứa `CRLFCRLF` để chứng minh parser lấy dấu phân cách ĐẦU TIÊN, giải thích vì sao phải dùng `--data-binary @-` chứ không `-d`, và vì sao `body_len` phải đếm byte thật thay vì đọc `Content-Length`); tôi tự chạy lại lệnh, tự giải base64 và đối chiếu 30 byte body |
| `TEST/TC-06_http-response/README.md` | AI soạn mô tả test case (thêm phiên 404 để có reason phrase hai từ, giải thích vì sao status line tách `split(" ", 2)` còn request line thì không, vì sao `status_code` phải là `int` — kèm ví dụ `"99" > "404"`); tôi tự chạy lại hai phiên curl và tự kiểm giá trị `ETag` giữ nguyên dấu nháy |
| `TEST/TC-13_http-nonstandard-port/README.md` | AI soạn mô tả test case (ghép hai phiên vào một file để kiểm cả hai nửa của ADR-5: HTTP ở port 8081 và payload lạ ở port 80; giải thích vì sao `UNKNOWN` ở tầng ứng dụng không làm `status` thành `unknown` trong khi ở tầng network/transport thì có); tôi tự chạy lại hai phiên và tự đối chiếu bốn dòng payload với thuật toán `detect()` |
| `idps/decode/dns.py` | AI viết parser DNS và giải thích cơ chế nén tên (hai bit cao `11` = con trỏ 14 bit), vì sao giải tên bằng vòng lặp chứ không đệ quy (I-6: độ sâu ngăn xếp không được phụ thuộc dữ liệu của kẻ tấn công), vì sao dùng **tập `seen` các offset đã đọc** thay vì bộ đếm số lần nhảy (chặn ngay lần lặp đầu, bắt được cả ca hai con trỏ trỏ vòng cho nhau), vì sao byte độ dài 64–191 là "loại nhãn reserved" chứ không phải "nhãn dài hơn 63", vì sao nhãn chứa byte lạ được escape `\xHH` thay vì bị từ chối như header HTTP (RFC 1035 cho phép octet bất kỳ, và đó là hình dạng của DNS tunneling), vì sao `qdcount`/`ancount` ghi con số bên gửi KHAI chứ không phải `len(questions)`; tôi đọc hiểu và tự dựng message bằng `struct` để đối chiếu từng byte |
| `tests/test_dns.py` | AI viết test cho query A, response có answer A với tên nén `0xC00C`, con trỏ trỏ vào giữa tên, CNAME có rdata nén, AAAA, type lạ giữ base64, ba ca con trỏ độc hại (tự trỏ, trỏ vòng đôi, ra ngoài payload — có đo thời gian < 1 s), nhãn loại reserved, tên > 255 byte, `ANCOUNT`/`QDCOUNT` khai quá, `rdlength` khai quá, nhãn nhị phân và 500 payload ngẫu nhiên có seed cố định; tôi đọc hiểu, chạy và tự sửa offset con trỏ để thấy tên đổi theo |
| `TEST/TC-03_udp/README.md` | AI soạn mô tả test case (ghép thêm datagram `nc` tới port 9999 để chứng minh trường UDP do parser UDP điền chứ không phải phần thừa của parser DNS; giải thích chuỗi hai phép trừ `total_length → length → payload_len` và vì sao `dig` gửi payload dài hơn message DNS sách vở — bản ghi OPT của EDNS0); tôi tự chạy lại lệnh và tự kiểm ba phép trừ trên cả 3 packet |
