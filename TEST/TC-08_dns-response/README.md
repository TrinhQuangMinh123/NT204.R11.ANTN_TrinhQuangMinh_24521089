# TC-08 — DNS response

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-8.2 (mỗi answer: name, type, TTL, data), REQ-8.3 (giải tên nén trong answer) |
| Task | T8.5 · Phase 8 |
| Ngày ghi | 2026-09-27 |
| Traffic | `dig @10.20.0.10 www.victim.lab A` (có answer) **và** `dig @10.20.0.10 victim.lab AAAA` (không có answer) |
| Kết quả | 4 packet, `processed=4 unknown=0 malformed=0` |
| `md5sum input.pcap` | `53b7929ca08aedb364e2905548ec72b9` |

## 1. Kịch bản

Truy vấn đầu hỏi **`www.victim.lab`** chứ không phải `victim.lab`. Hai lý do:

1. Nó chứng minh cấu hình `address=/victim.lab/10.20.0.10` của dnsmasq khớp **cả tên con** (chốt ở
   T1.5), nên answer mang tên `www.victim.lab` — tên **dài hơn** tên trong TC-07.
2. Tên dài hơn làm **nén tên** đáng giá hơn: trên dây, tên của answer chỉ là **2 byte** `c0 0c` thay
   cho 16 byte, và đó chính là thứ REQ-8.3 yêu cầu giải được.

Truy vấn thứ hai (`AAAA`) cho một response **không có answer nào** để đối chiếu: cùng một parser, cùng
một đường đi, `answers` là `[]` và vẫn `status="ok"`.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-08_dns-response
docker compose exec -T attacker tcpdump -i eth0 -U -c 4 -w - \
    'udp and host 10.20.0.10 and port 53' > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker dig @10.20.0.10 www.victim.lab A
sleep 1
docker compose exec -T attacker dig @10.20.0.10 victim.lab AAAA
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

## 3. Kết quả mong đợi

Điều kiện dừng của T8.5: dòng `"qr":"response"` có `answers` ≥ 1 phần tử gồm `name`, `type`, `ttl`, và
`data` là một địa chỉ IPv4.

## 4. Kết quả thực tế

```sh
$ grep -o '"answers":\[[^]]*\]*}*\]' TEST/TC-08_dns-response/output.jsonl
"answers":[]
"answers":[{"name":"www.victim.lab","type":"A","ttl":300,"data":"10.20.0.10"}]
"answers":[]
"answers":[]
$ cat TEST/TC-08_dns-response/run.log
processed=4 unknown=0 malformed=0
```

Packet 2 có đúng 1 answer với cả 4 trường, `data` là `"10.20.0.10"` dạng chấm → **đạt**.

| # | `qr` | `rcode` | `qdcount`/`ancount` | question | answers |
|---|---|---|---|---|---|
| 1 | query | NOERROR | 1 / 0 | `www.victim.lab` · A | `[]` |
| 2 | response | NOERROR | 1 / **1** | `www.victim.lab` · A | `www.victim.lab` · A · 300 · `10.20.0.10` |
| 3 | query | NOERROR | 1 / 0 | `victim.lab` · AAAA | `[]` |
| 4 | response | REFUSED | 1 / 0 | `victim.lab` · AAAA | `[]` |

## 5. Toàn bộ packet 2, từng byte

```
offset  bytes                       ý nghĩa
  0     b3 0d                       id = 45837  (bằng id của packet 1)
  2     85 80                       flags: QR=1 AA=1 RD=1 RA=1, rcode=0 (NOERROR)
  4     00 01                       QDCOUNT = 1
  6     00 01                       ANCOUNT = 1
  8     00 00                       NSCOUNT = 0
 10     00 01                       ARCOUNT = 1   (bản ghi OPT của EDNS0)
--- question ---
 12     03 "www" 06 "victim" 03 "lab" 00     tên đầy đủ, 16 byte
 28     00 01                       QTYPE  = A
 30     00 01                       QCLASS = IN
--- answer ---
 32     c0 0c                       NAME = con trỏ nén -> offset 12
 34     00 01                       TYPE = A
 36     00 01                       CLASS = IN
 38     00 00 01 2c                 TTL = 300
 42     00 04                       RDLENGTH = 4
 44     0a 14 00 0a                 RDATA = 10.20.0.10
--- additional ---
 48     00 00 29 04 d0 …            OPT (EDNS0) — parser bỏ qua (Phụ lục A.6)
```

### 5.1 Con trỏ nén `c0 0c` (REQ-8.3)

```
c0 0c  =  1100 0000 0000 1100
          ^^                    hai bit cao = 11  -> đây là CON TRỎ, không phải nhãn
            ^^ ^^^^ ^^^^ ^^^^   14 bit còn lại = 12 -> nhảy về offset 12
```

Offset 12 là đầu tên trong question, nên tên của answer đọc ra đúng `www.victim.lab`. Hai byte thay
cho 16 byte — và cũng là chỗ một parser viết sơ sài sẽ sai theo một trong ba cách:

| Cách cài sai | Kết quả |
|---|---|
| Coi `c0` là byte độ dài của một nhãn thường (192 byte) | đọc tràn ra ngoài payload → mất answer |
| Giải bằng đệ quy | message dựng tay có con trỏ lồng nhiều tầng → `RecursionError` = lỗi `internal` |
| Vòng lặp không kiểm | con trỏ trỏ vào chính nó (`c0 0c` đặt tại offset 12) → **treo vĩnh viễn** |

Parser ở đây dùng vòng lặp + **tập `seen` các offset đã đọc**: gặp lại một offset = vòng lặp, báo lỗi
và dừng ngay (I-6). Ba ca độc hại đó kiểm bằng message dựng tay trong `tests/test_dns.py`
(`test_pointer_loop` có **đo thời gian < 1 s**, `test_pointer_loop_between_two_pointers`,
`test_pointer_out_of_range`) vì không server nào gửi chúng.

### 5.2 `ttl = 300` không phải mặc định

dnsmasq trả TTL **0** cho các bản ghi khai bằng `address=`. Cấu hình `local-ttl=300` được thêm ở T1.5
**chính vì** test case này: với TTL 0 thì cột `ttl` trong event luôn là `0` và không chứng minh được
parser đọc đúng 4 byte đó (`00 00 01 2c` = 300).

## 6. Nhận xét

- **`dig` hỏi AAAA thì dnsmasq trả `REFUSED`, không phải NODATA.** Vì `address=/victim.lab/10.20.0.10`
  chỉ khai một bản ghi A, và `no-resolv` nghĩa là lab không có upstream để hỏi tiếp — nên dnsmasq từ
  chối thay vì trả lời "có tên nhưng không có bản ghi AAAA". Đây là hành vi của **lab**, không phải
  của parser; ghi lại ở đây để lần chạy sau không tưởng là lỗi.
- `data` của answer là chuỗi `"10.20.0.10"` chứ không phải 4 byte thô: RDATA của bản ghi A luôn đúng
  4 byte nên đổi sang dạng chấm là **đảo ngược được** và so sánh trực tiếp được với `src_ip`/`dst_ip`
  của event — thứ luật phát hiện cần khi đối chiếu "tên này trả về IP nào". Với type chưa hỗ trợ,
  `data` là base64 của RDATA nguyên bản, nên không bao giờ mất dữ liệu (I-4).
- `questions` của packet 2 và 4 **được parse lại** từ chính response (response nhắc lại question), nên
  event của một response độc lập với event của query — không cần ghép flow mới biết nó trả lời cho tên
  nào. Đó là lý do `qdcount` vẫn là 1 ở cả response.
