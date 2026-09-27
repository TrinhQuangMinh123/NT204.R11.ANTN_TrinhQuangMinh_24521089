# TC-07 — DNS query

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-8.1 (transaction ID, domain được hỏi, query type), REQ-10.2 (nhận diện DNS bằng cấu trúc payload) |
| Task | T8.4 · Phase 8 |
| Ngày ghi | 2026-09-27 |
| Traffic | `dig @10.20.0.10 victim.lab A` (trong zone) **và** `dig @10.20.0.10 khong-ton-tai.example A` (ngoài zone) |
| Kết quả | 4 packet, `processed=4 unknown=0 malformed=0` |
| `md5sum input.pcap` | `059d852fb963b6d18b9b46de32bf8ea5` |

## 1. Kịch bản

Hai truy vấn, khác nhau đúng ở chỗ tên được hỏi **nằm trong** hay **ngoài** zone của dnsmasq:

| Truy vấn | Tên | Đáp lại của dnsmasq |
|---|---|---|
| 1 | `victim.lab` | `NOERROR`, 1 answer (TC-08 soi kỹ phần này) |
| 2 | `khong-ton-tai.example` | `REFUSED`, 0 answer (`no-resolv`: lab không có upstream) |

Cặp thứ hai có hai giá trị riêng: nó cho một tên **dài hơn và có dấu gạch ngang** (13 nhãn + 7 nhãn,
trong khi `victim.lab` chỉ 6 + 3), và nó cho một `rcode` khác `NOERROR` cùng một response **không có
answer nào** — ca mà `answers: []` phải là danh sách rỗng chứ không phải lỗi.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-07_dns-query
docker compose exec -T attacker tcpdump -i eth0 -U -c 4 -w - \
    'udp and host 10.20.0.10 and port 53' > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker dig @10.20.0.10 victim.lab A
sleep 1
docker compose exec -T attacker dig @10.20.0.10 khong-ton-tai.example A
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

`-c 4` = 2 query + 2 response (lý do dùng `-c` ở `TC-02/README.md` §2).

## 3. Kết quả mong đợi

Điều kiện dừng của T8.4: có dòng `"qr":"query"` với `questions` chứa **đúng tên miền đã hỏi** và
`"type":"A"`.

## 4. Kết quả thực tế

```sh
$ grep -o '"qr":"[^"]*"' TEST/TC-07_dns-query/output.jsonl
"qr":"query"
"qr":"response"
"qr":"query"
"qr":"response"
$ grep -o '"questions":\[[^]]*\]' TEST/TC-07_dns-query/output.jsonl
"questions":[{"name":"victim.lab","type":"A"}]
"questions":[{"name":"victim.lab","type":"A"}]
"questions":[{"name":"khong-ton-tai.example","type":"A"}]
"questions":[{"name":"khong-ton-tai.example","type":"A"}]
$ cat TEST/TC-07_dns-query/run.log
processed=4 unknown=0 malformed=0
```

Tên trong event **khớp từng ký tự** với tên đã gõ trên dòng lệnh, `type` là `"A"` → **đạt**.

Khoá `app` của bốn packet:

| # | `id` | `qr` | `opcode` | `rcode` | `qdcount`/`ancount` | `questions[0]` |
|---|---|---|---|---|---|---|
| 1 | 57178 | query | QUERY | NOERROR | 1 / 0 | `victim.lab` · A |
| 2 | 57178 | response | QUERY | NOERROR | 1 / 1 | `victim.lab` · A |
| 3 | 40123 | query | QUERY | NOERROR | 1 / 0 | `khong-ton-tai.example` · A |
| 4 | 40123 | response | QUERY | **REFUSED** | 1 / 0 | `khong-ton-tai.example` · A |

## 5. Đối chiếu từng byte với payload

Packet 1, 32 byte đầu (từ `payload_b64` của UDP):

```
df 5a | 01 20 | 00 01 | 00 00 | 00 00 | 00 01 | 06 "victim" 03 "lab" 00 | 00 01 | 00 01 | 00 00 29 …
  id    flags   qd=1    an=0    ns=0    ar=1    tên: nhãn 6 + nhãn 3 + root  QTYPE  QCLASS  OPT (EDNS0)
```

- **`id` = 0xdf5a = 57178**, và packet 2 mang **đúng** con số đó. Đây là lý do REQ-8.1 đòi transaction
  ID: nó là thứ duy nhất ghép một response với query của nó (UDP không có kết nối). Một response mang
  `id` mà không client nào hỏi chính là hình dạng của DNS cache poisoning.
- **`flags` = 0x0120** → bit 15 (QR) = 0 → `"query"`; 4 bit opcode = 0 → `QUERY`; 4 bit thấp = 0 →
  `NOERROR`. Packet 2 có `0x8580` (QR=1, AA, RD, RA) và packet 4 có `0x8185` → 4 bit thấp = 5 →
  `REFUSED`.
- **Tên không có dấu chấm trên dây.** Dấu phân cách là **byte độ dài** đứng trước mỗi nhãn:
  `06 victim 03 lab 00`. Chuỗi `"victim.lab"` trong event là do parser ghép lại bằng `".".join()`;
  byte `00` cuối là nhãn gốc (root) — chỗ kết thúc tên. Packet 3 thấy rõ hơn: `0d` = 13 =
  `"khong-ton-tai"`, `07` = 7 = `"example"`.
- **`ar` = 1** nhưng event không có khoá nào cho additional section: `dig` gửi thêm bản ghi OPT
  (EDNS0). Phụ lục A.6 chỉ yêu cầu question + answer nên parser bỏ qua phần này — và **không** báo
  lỗi cho số byte còn lại (xem `TC-03/README.md` §7).

## 6. `ancount=0` không phải lỗi

Packet 4 (`REFUSED`) có `ancount: 0`, `answers: []`, `errors: []`, `status: "ok"`. Vòng lặp đọc answer
chạy `range(0)` → không lặp lần nào, nên không có gì để sai. REQ-8.5 nói về ca **ngược lại**: khai
nhiều hơn số bản ghi thật (`ANCOUNT=5` mà chỉ có 1 answer) — ca đó kiểm bằng message dựng tay trong
`tests/test_dns.py::test_ancount_larger_than_actual_keeps_parsed_answers`, vì một server thật không
bao giờ gửi như vậy.

## 7. Nhận xét

- Cả 4 packet có `detect_method="port+payload"`: port 53 đưa DNS vào nhóm thử đầu tiên, và
  `matches_dns()` — tức **thử parse trọn phần question** — khớp. DNS là giao thức duy nhất trong bài
  không có chuỗi mở đầu để so: 2 byte đầu là transaction ID nên cả 65536 giá trị đều hợp lệ. Ca
  `detect_method="payload"` (DNS trên port 5353, REQ-11.2) kiểm bằng `tests/test_detector.py`.
- Event **không** ghi các cờ AA/TC/RD/RA: tập khoá của `app` đã chốt ở design §5.4 (`id`, `qr`,
  `opcode`, `rcode`, `qdcount`, `ancount`, `questions`, `answers`) và I-2 buộc mọi event dùng **cùng
  một** tập khoá, nên không được tự thêm khoá giữa bài. Cờ TC (truncated) sẽ cần khi hỗ trợ DNS over
  TCP — nằm ngoài phạm vi bài 1 (A3).
- `rcode` ghi thành **tên** (`"REFUSED"`) chứ không phải số 5, khác với `status_code` của HTTP (số).
  Lý do: rcode là tập 16 giá trị rời rạc, không ai so sánh theo khoảng; còn status code HTTP thì luật
  phát hiện so theo khoảng (4xx, 5xx) nên phải là số. Mã lạ vẫn giữ con số dưới dạng `"RCODE13"`.
