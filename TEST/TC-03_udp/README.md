# TC-03 — UDP

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-6.1 (port và độ dài UDP vào event), REQ-6.2 (`length` khai sai → malformed), I-4 |
| Task | T8.3 · Phase 8 |
| Ngày ghi | 2026-09-27 |
| Traffic | `dig @10.20.0.10 victim.lab A` (2 datagram) **và** `printf hello \| nc -u 10.20.0.10 9999` (1 datagram) |
| Kết quả | 3 packet, `processed=3 unknown=0 malformed=0` |
| `md5sum input.pcap` | `44da3d9a0ec1d91a3d77a75ab5dbdb1c` |

## 1. Kịch bản

Hai loại datagram UDP, cố ý khác nhau ở **mọi** thứ trừ việc cùng là UDP:

| # | Cặp port | Payload | Vai trò trong test case |
|---|---|---|---|
| 1, 2 | 56251 ↔ 53 | message DNS (51 và 55 byte) | UDP mang một giao thức bài có parser |
| 3 | 45329 → 9999 | `hello` (5 byte) | UDP mang dữ liệu bài **không** có parser |

Cặp thứ hai quan trọng đúng bằng cặp thứ nhất: nó chứng minh các trường UDP trong event được điền
bởi **parser UDP**, không phải "phần thừa" của parser DNS. Port 9999 trên victim không có ai nghe,
nên đây cũng là hình dạng của một bước UDP scan.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-03_udp
docker compose exec -T attacker tcpdump -i eth0 -U -c 3 -w - \
    'udp and host 10.20.0.10' > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker dig +short @10.20.0.10 victim.lab A
sleep 1
docker compose exec -T attacker sh -c "printf 'hello' | nc -u -w1 10.20.0.10 9999"
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

Filter `udp and host 10.20.0.10` (**không** lọc theo port) để bắt được cả datagram gửi tới port 9999.
`-c 3` = 2 datagram DNS + 1 datagram `nc`, tcpdump tự thoát (lý do ở `TC-02/README.md` §2).

## 3. Kết quả mong đợi

Điều kiện dừng của T8.3: có dòng `"transport_proto":"UDP"` với `"udp":{` chứa `src_port`, `dst_port`,
`length`, `payload_len`.

## 4. Kết quả thực tế

```sh
$ grep -c '"transport_proto":"UDP"' TEST/TC-03_udp/output.jsonl
3
$ grep -o '"udp":{[^}]*}' TEST/TC-03_udp/output.jsonl     # đã lược payload_b64
"udp":{"src_port":56251,"dst_port":53,"length":59,"payload_len":51,"payload_b64":"…"}
"udp":{"src_port":53,"dst_port":56251,"length":63,"payload_len":55,"payload_b64":"…"}
"udp":{"src_port":45329,"dst_port":9999,"length":13,"payload_len":5,"payload_b64":"…"}
$ cat TEST/TC-03_udp/run.log
processed=3 unknown=0 malformed=0
```

Cả 3 dòng có đủ 5 khoá của Phụ lục A.4 → **đạt**.

## 5. `length` — con số tự khai duy nhất trong bài

UDP là giao thức **duy nhất** ở bài này tự khai độ dài của chính nó, và `length` tính **cả 8 byte
header**. Ba dòng trên khớp nhau qua hai phép trừ ở hai tầng:

```
length     = ipv4.total_length - ihl*4
payload_len = length - 8
packet 1:  59 = 79 - 20      51 = 59 - 8      ✓
packet 2:  63 = 83 - 20      55 = 63 - 8      ✓
packet 3:  13 = 33 - 20       5 = 13 - 8      ✓
```

Vì `length` do bên gửi khai nên nó **có thể** không khớp dữ liệu thật — đó là REQ-6.2. Parser so
**BẰNG** (`length != len(data)` → lỗi), không chỉ so lớn hơn: IPv4 đã cắt payload theo `total_length`
trước khi giao xuống, nên `len(data)` là độ dài datagram thật; `length` nhỏ hơn nghĩa là trong packet
còn byte **không ai nhận**, thường là dấu hiệu dữ liệu dựng bằng tay. Traffic thật ở đây khớp cả 3
lần → `malformed=0`; ca khai sai kiểm bằng packet dựng tay trong `tests/test_udp.py` (có ca quét mọi
`length` từ 0..39 để chứng minh **đúng một** giá trị được nhận).

Parser **không** kiểm checksum UDP: với IPv4 checksum là **tuỳ chọn**, giá trị 0 nghĩa là bên gửi
không tính (RFC 768) — kiểm sẽ báo sai trên datagram hoàn toàn hợp lệ.

## 6. Tầng ứng dụng của ba datagram

| # | `app_proto` | `detect_method` | `app` |
|---|---|---|---|
| 1 | `DNS` | `port+payload` | query, `questions=[{name: victim.lab, type: A}]` |
| 2 | `DNS` | `port+payload` | response, `answers=[{victim.lab, A, 300, 10.20.0.10}]` |
| 3 | `UNKNOWN` | `null` | `null` |

Packet 3 ra `UNKNOWN` vì payload `hello` chỉ có 5 byte < 12 byte header DNS, nên `matches_dns()` trả
`False` ngay ở điều kiện đầu — và trong bài chưa có giao thức UDP nào khác. `status` vẫn `"ok"`
(ADR-14): "bài chưa có parser cho dữ liệu này" không phải lỗi.

## 7. Nhận xét

- **Datagram DNS thật dài hơn message DNS "sách vở".** `dig` gửi thêm một bản ghi OPT (EDNS0) ở
  additional section, nên payload 51 byte trong khi phần header + question chỉ 28 byte. Parser DNS
  **cố tình** không đọc authority/additional (Phụ lục A.6 chỉ yêu cầu question + answer), và byte còn
  lại sau answer cuối **không** bị coi là lỗi — khác UDP (`length` phải khớp đúng), vì ở DNS các con
  số đếm trong header đã nói rõ phần nào thuộc phần nào.
- **ICMP port unreachable không có trong file.** Victim không nghe port 9999 nên kernel của nó trả
  ICMP; filter `udp` loại packet đó ra. Ca ICMP (`transport_proto="UNKNOWN"`) là việc của TC-11.
- Port nguồn của `dig` và `nc` do kernel chọn → mỗi lần bắt lại sẽ khác. `input.pcap` đã commit mới
  là bằng chứng cố định (V8.2 chạy lại từ chính nó và so `diff`).
