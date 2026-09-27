# TC-01 — TCP handshake

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-5.2 (cờ TCP thành danh sách tên), REQ-5.1, REQ-5.3, REQ-4.1 |
| Task | T5.5 · Phase 5 |
| Ngày ghi | 2026-09-27 |
| Traffic | một lần `curl http://10.20.0.10/` từ `attacker` sang `victim`, đi xuyên sensor |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0` |
| `md5sum input.pcap` | `a138617f9e32ce108985dce6e67a19b6` |

## 1. Mục tiêu

Chứng minh **ba packet của một handshake phân biệt được CHỈ bằng trường `flags`** trong event
(REQ-5.2), trên traffic thật chứ không phải packet dựng tay như `tests/test_tcp.py`.

## 2. Cách ghi lại

Bắt gói trên `attacker` (interface `eth0`), ghi ra **stdout**, shell của host hứng lại — nhờ vậy file
thuộc về user host và container không cần quyền ghi vào repo (ADR-16):

```sh
docker compose exec -T attacker timeout 12 tcpdump -i eth0 -U -w - \
    'tcp and host 10.20.0.10 and port 80' > TEST/TC-01_tcp-handshake/input.pcap &
sleep 4
docker compose exec -T attacker curl -s -o /dev/null http://10.20.0.10/
```

**Vì sao filter là `tcp and host 10.20.0.10 and port 80`:** nó loại ARP và mọi traffic khác, nên
packet đầu tiên trong file chắc chắn là packet đầu tiên của kết nối. Một kết nối TCP chỉ có **một**
cách mở (RFC 9293), nên ba packet đầu **bắt buộc** là SYN → SYN/ACK → ACK; không cần lọc theo cờ.

`-U` (ghi từng packet, không đệm) để file vẫn hợp lệ khi `timeout` gửi SIGTERM cho `tcpdump`.

> **Cảnh báo khi chạy lại lệnh trên (thêm 2026-09-27, sau T7.1).** `timeout 12` trong container **không
> đáng tin trên máy WSL2 này**: nó đã một lần không bắn SIGALRM (`/proc/<pid>/timers` còn treo
> `signal: 14` sau hơn một giờ), nên `tcpdump` sống sót và **vẫn giữ fd ghi vào chính
> `TEST/TC-01_tcp-handshake/input.pcap`** — traffic của test case ghi sau đó bị ghi thêm vào file bằng
> chứng này (phát hiện bằng `git status`, đã `git restore` về đúng blob `md5 a138617f…`). Từ TC-02 trở
> đi mọi test case dùng `tcpdump -c <số packet>` để tcpdump **tự thoát**; xem
> `TEST/TC-02_tcp-data/README.md` §2. Nếu chạy lại TC-01, nên thay `timeout 12` bằng `-c 10` và kiểm
> `ps -ef | grep tcpdump` rỗng sau khi bắt xong.

Chạy parser:

```sh
docker compose run --rm idps-offline python main.py \
    --pcap TEST/TC-01_tcp-handshake/input.pcap \
    -o TEST/TC-01_tcp-handshake/output.jsonl 2>&1 | tee TEST/TC-01_tcp-handshake/run.log
```

`run.log` chỉ giữ output của **chương trình**; các dòng `Container … Creating` của Docker Compose đã
bị lọc bỏ vì chúng chứa id container sinh ngẫu nhiên mỗi lần chạy, sẽ làm bằng chứng không lặp lại được.

## 3. Điều kiện dừng

```sh
$ grep -o '"flags":\[[^]]*\]' TEST/TC-01_tcp-handshake/output.jsonl | head -3
"flags":["SYN"]
"flags":["SYN","ACK"]
"flags":["ACK"]
```

Ba giá trị khác nhau đôi một → REQ-5.2 đạt.

## 4. Toàn bộ 10 packet

| # | Chiều | `flags` | `data_offset` | `payload_len` | Ý nghĩa |
|---|---|---|---|---|---|
| 1 | attacker → victim | `["SYN"]` | 10 | 0 | xin mở kết nối |
| 2 | victim → attacker | `["SYN","ACK"]` | 10 | 0 | đồng ý + xác nhận SYN |
| 3 | attacker → victim | `["ACK"]` | 8 | 0 | xác nhận → kết nối mở |
| 4 | attacker → victim | `["PSH","ACK"]` | 8 | 74 | `GET / HTTP/1.1` |
| 5 | victim → attacker | `["ACK"]` | 8 | 0 | xác nhận đã nhận request |
| 6 | victim → attacker | `["PSH","ACK"]` | 8 | 239 | `HTTP/1.1 200 OK` |
| 7 | attacker → victim | `["ACK"]` | 8 | 0 | xác nhận đã nhận response |
| 8 | attacker → victim | `["FIN","ACK"]` | 8 | 0 | attacker hết dữ liệu |
| 9 | victim → attacker | `["FIN","ACK"]` | 8 | 0 | victim cũng hết dữ liệu |
| 10 | attacker → victim | `["ACK"]` | 8 | 0 | đóng xong (4 bước) |

## 5. Vì sao test case này còn kiểm được REQ-5.3

Cột `data_offset` **không có giá trị 5 nào cả**: mọi segment đều có TCP options.

- Packet 1–2: `data_offset=10` → header **40 byte** (20 byte options: MSS, SACK permitted,
  timestamp, window scale).
- Packet 3–10: `data_offset=8` → header **32 byte** (12 byte options: timestamp + 2 nop).

Nếu parser giả định header TCP dài 20 byte thì payload của packet 4 sẽ bắt đầu sớm **12 byte**, và
thay vì `GET / HTTP/1.1` sẽ đọc ra 12 byte options rồi mới tới `GET`. Sai này **im lặng** — vẫn ra
bytes, không có lỗi nào báo — nên nó chỉ lộ ra ở đúng loại bằng chứng này.

Kiểm lại I-4 (base64 giải mã ngược ra đúng bytes gốc) trên packet 4:

```
b'GET / HTTP/1.1\r\nHost: 10.20.0.10\r\nUser-Agent: curl/8.14.1\r\nA...'   (74 byte)
```

## 6. Ghi chú

- **Cập nhật 2026-09-27 (sau T6.4):** `output.jsonl` và `run.log` đã được ghi lại từ **chính
  `input.pcap` đã commit**, bằng đúng lệnh ở §2 — nên test case vẫn tái lập được. So với bản ghi ở
  Phase 5: 8/10 dòng **giống hệt từng byte**; packet 4 và 6 chỉ đổi ở ba khoá tầng ứng dụng
  (`app_proto`, `detect_method`, `app`) từ `null` sang giá trị thật:

  | # | `app_proto` | `detect_method` | `app` |
  |---|---|---|---|
  | 4 | `"HTTP"` | `"port+payload"` | `kind=request`, `method=GET`, `uri=/`, 3 header, `body_len=0` |
  | 6 | `"HTTP"` | `"port+payload"` | `kind=response`, `status_code=200`, `reason=OK`, 8 header, `body_len=11` |

  Đây là nội dung thật của V6.3: `diff` với bản cũ **không** rỗng (vì Phase 6 thêm một tầng cho đúng
  hai packet có payload), nhưng mọi khoá của tầng liên kết / network / transport **không đổi một
  byte** — tức Phase 6 không làm hồi quy Phase 5. Bằng chứng cũ được thay bằng một **commit mới**,
  không sửa lịch sử git.
- `detect_method` là `"port+payload"` ở cả hai dòng vì traffic này chạy trên port 80. Ca
  `"payload"` (port 8081) nằm ở TC-13 — Phase 7.
- `ipv4.ihl` = 5 ở mọi packet (không có IP options), nên ca IHL > 5 chỉ kiểm được bằng packet dựng
  tay trong `tests/test_ipv4.py`.
- `ethernet.src_mac` / `dst_mac` là MAC của attacker và của **sensor** (không phải của victim): trên
  chặng `attacker → sensor`, victim nằm sau một router nên MAC đích là MAC của cổng `ext0` của sensor.
