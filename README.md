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

Toàn bộ hệ thống chạy bằng **Docker Compose**: bốn service trên hai mạng ảo, trong đó cảm biến
(`idps`) nằm **giữa** hai mạng và là đường đi duy nhất giữa chúng. Nhờ vậy mọi gói attacker ↔ victim
đều buộc phải đi qua cảm biến, và từng kịch bản test tái hiện lại được trong môi trường cô lập.

```
        net_ext 10.10.0.0/24                       net_int 10.20.0.0/24
   ┌──────────────┐                 ┌───────────┐                 ┌──────────────┐
   │   attacker   │ eth0       ext0 │   idps    │ int0       eth0 │    victim    │
   │  10.10.0.10  │────────────────►│ .254/.254 │────────────────►│  10.20.0.10  │
   │ curl dig nc  │                 │  sensor   │                 │ nginx dnsmasq│
   │   tcpdump    │                 │  (router) │                 │   aiosmtpd   │
   └──────────────┘                 └─────┬─────┘                 └──────────────┘
                                          │ main.py --interface int0
                                          ▼
                                   events JSON Lines
   ┌──────────────┐
   │ idps-offline │  main.py --pcap TEST/<tc>/input.pcap  (không mạng, không capability)
   └──────────────┘
```

### 2.1 Các service

| Service | Image | Vai trò | Quyền |
|---|---|---|---|
| `idps` | `idps` | Cảm biến: kernel của nó chuyển tiếp gói giữa hai mạng (`net.ipv4.ip_forward=1`), Python chỉ **nghe** trên `int0` | root, `cap_drop: ALL` + `cap_add: NET_RAW` (mở AF_PACKET) |
| `idps-offline` | `idps` (**cùng image** với `idps`) | Chế độ `--pcap`: chạy mọi test case trong `TEST/`, chạy `pytest` | UID/GID của user host, `cap_drop: ALL`, `network_mode: none` |
| `attacker` | `idps-attacker` | Sinh traffic (`curl`, `dig`, `nc`), ghi PCAP tham chiếu (`tcpdump`) | `cap_drop: ALL` + `NET_ADMIN`, `NET_RAW`, `SETUID`, `SETGID` |
| `victim` | `idps-victim` | Dịch vụ đích: nginx (`:80`, `:8081`), dnsmasq (`:53`, zone `victim.lab`), aiosmtpd (`:25`) | `cap_drop: ALL` + `NET_ADMIN`, `NET_BIND_SERVICE`, `CHOWN`, `SETUID`, `SETGID` |

`idps` và `idps-offline` build từ **một image duy nhất**, tức chế độ live và chế độ PCAP chạy **cùng một
mã nguồn** — điều kiện để test E2E ở `TEST/E2E-01_live-vs-pcap/` có nghĩa.

### 2.2 Mạng và địa chỉ

| Mạng | Subnet | Thành viên |
|---|---|---|
| `net_ext` | `10.10.0.0/24` | `attacker` `10.10.0.10` · `idps` `ext0` `10.10.0.254` |
| `net_int` | `10.20.0.0/24` | `idps` `int0` `10.20.0.254` · `victim` `10.20.0.10` |

IP khai cố định trong `compose.yaml` (không dùng IP động của Docker) để bằng chứng test lặp lại được.
Tính chất "chỉ có một đường giữa hai mạng" **không** dựa vào `internal: true` — nó dựa vào việc
`attacker` và `victim` mỗi bên chỉ có đúng một route sang mạng kia, trỏ vào cảm biến, và default route bị
xoá lúc khởi động. Kiểm chứng: tắt `idps` thì `curl` từ attacker thất bại.

### 2.3 Công nghệ và phiên bản

| Thành phần | Chốt ở |
|---|---|
| `python:3.12.14-slim` (image cảm biến) | `Dockerfile` |
| `scapy==2.7.0` — **chỉ** dùng để lấy bytes thô + nhãn thời gian (`recv_raw`, `RawPcapReader`); không dùng bộ bóc tách của nó | `requirements.txt` |
| `pytest==9.1.1` | `requirements.txt` |
| `debian:13-slim` (image `attacker`, `victim`) | `lab/attacker/Dockerfile`, `lab/victim/Dockerfile` |

Mọi parser (Ethernet, IPv4, TCP, UDP, HTTP, DNS, SMTP) đều tự viết bằng `struct` và phép so sánh biên,
không dùng thư viện bóc tách nào.

### 2.4 Bố cục mã nguồn

```
main.py                 CLI: chọn nguồn, nối các tầng, in thống kê
idps/capture/           live.py (AF_PACKET), pcap.py (đọc file PCAP)  ← nơi DUY NHẤT import Scapy
idps/core/              frame.py, event.py, runner.py, sink.py, stats.py
idps/decode/            ethernet.py → ipv4.py → tcp.py / udp.py → detector.py → http.py / dns.py / smtp.py
                        pipeline.py (process_frame: một frame → một event), common.py (ParseResult, need)
idps/output/jsonl.py    ghi JSON Lines, flush từng dòng
tests/                  595 test; tests/tools/make_bad_pcaps.py sinh PCAP lỗi cho TC-11/TC-12
TEST/                   bằng chứng test: mỗi thư mục con một test case
```

Một frame vào, **đúng một** dòng JSON ra — kể cả khi packet hỏng hay không nhận ra giao thức; lúc đó
event mang `status` = `malformed`/`unknown` và danh sách `errors` chỉ rõ tầng nào phát hiện.

### 2.5 Cách chạy

```sh
# UID/GID của host phải được export để file do idps-offline ghi ra thuộc về user host
export HOST_UID=$(id -u) HOST_GID=$(id -g)

docker compose build                          # dựng cả ba image
docker compose up -d idps attacker victim     # chỉ cần khi muốn sinh traffic mới
```

Chế độ PCAP (không cần mạng, không cần quyền gì):

```sh
docker compose run --rm idps-offline python main.py --pcap <file.pcap> -o <out.jsonl>
```

Chế độ live trên cảm biến (`docker compose exec -T` **không** truyền tín hiệu vào container, nên PID
được ghi ra file rồi gửi `SIGTERM` bằng một lệnh thứ hai — SIGTERM là đường dừng êm: đóng file, in thống
kê, exit 0):

```sh
docker compose exec -T idps sh -c \
    'python main.py --interface int0 -o /tmp/live.jsonl & echo $! > /tmp/live.pid; wait'
# ... sinh traffic ở cửa sổ khác, rồi:
docker compose exec -T idps sh -c 'kill -TERM $(cat /tmp/live.pid)'
docker compose exec -T idps cat /tmp/live.jsonl > live.jsonl
```

Bộ test:

```sh
docker compose run --rm idps-offline python -m pytest -q      # 595 passed
```

### 2.6 Chạy lại một test case

Mỗi thư mục con của `TEST/` có `input*.pcap` (đầu vào đã commit), `output*.jsonl` (kết quả đã commit),
`run.log` và `README.md` mô tả kịch bản + cách tái hiện. Chạy lại một test case là chạy lại đúng file
PCAP đó và so sánh — kết quả phải giống **từng byte**:

```sh
TC=TEST/TC-04_http-get
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap -o $TC/output.jsonl
git status --short $TC        # không in gì  →  output khớp từng byte với bản đã commit
```

Chạy lại **toàn bộ** bằng chứng (16 tệp output của 14 test case):

```sh
for f in TEST/*/input*.pcap; do
    d=$(dirname "$f"); b=$(basename "$f" .pcap)
    case "$d" in *E2E-01*) out="$d/pcap.jsonl";; *) out="$d/${b/input/output}.jsonl";; esac
    docker compose run --rm idps-offline python main.py --pcap "$f" -o "$out" > /dev/null
done
git status --short TEST/       # rỗng  →  cả 16 tệp khớp từng byte
```

`live.jsonl` của `E2E-01` là ngoại lệ duy nhất không tái sinh được bằng lệnh trên: nó đến từ một lần bắt
gói trực tiếp, nên nhãn thời gian và số hiệu cổng của lần chạy sau sẽ khác. Cách kiểm chứng nó nằm trong
`TEST/E2E-01_live-vs-pcap/README.md`.

## 3. Chức năng dự kiến

| # | Task | Trạng thái | Bằng chứng / ghi chú |
|---|------|-----------|---|
| 1 | Thu thập packet | ☑ | `idps/capture/live.py` (AF_PACKET), `idps/capture/pcap.py`; live và PCAP cho cùng kết quả — `TEST/E2E-01_live-vs-pcap/` |
| 2 | Parser TCP, UDP | ☑ | `idps/decode/tcp.py`, `udp.py` (và `ethernet.py`, `ipv4.py` bên dưới); TC-01, TC-02, TC-03 |
| 3 | Parser DNS, HTTP | ☑ | `idps/decode/http.py`, `dns.py`, thêm `smtp.py` ngoài yêu cầu; TC-04…TC-08, TC-09, TC-10, TC-13 |
| 4 | Trích xuất feature | ☐ | bài sau; mọi event đã có đủ 5-tuple để ghép theo flow |
| 5 | Phát hiện port scan | ☐ | bài sau |
| 6 | Cảnh báo và ghi log | ☐ | bài sau; bài 1 đã có bộ ghi JSON Lines `idps/output/jsonl.py` |
| 7 | Chức năng chặn (IPS) | ☐ | bài sau; sẽ cần thêm capability `NET_ADMIN` cho cảm biến |
| 8 | Test cases | ☑ | phạm vi bài 1: 14 test case trong `TEST/` (13 TC + 1 E2E), 595 test đơn vị trong `tests/` |

Packet lạ và packet hỏng cũng có bằng chứng riêng: TC-11 (`UNKNOWN` ở cả bốn tầng), TC-12 (10 loại lỗi,
0 lỗi `internal`, exit 0).

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
có thể giải thích từng dòng mã nguồn trong repo này.