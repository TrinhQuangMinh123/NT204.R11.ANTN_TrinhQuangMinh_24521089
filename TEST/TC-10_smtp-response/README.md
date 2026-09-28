# TC-10 — SMTP response

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-9.2 (status code dạng số nguyên + nội dung dòng), REQ-9.3 (response nhiều dòng → một status code chung, đủ các dòng), REQ-11.3 (SMTP trên port không chuẩn) |
| Task | T9.4 · Phase 9 |
| Ngày ghi | 2026-09-27 |
| Traffic | `input.pcap`: chiều reply của **cùng phiên** như TC-09 (aiosmtpd, port 25) · `input-multiline.pcap`: một reply nhiều dòng gửi trong **một lần ghi** từ port 2525 |
| Kết quả | 9 packet + 1 packet, `processed=9` và `processed=1`, `unknown=0 malformed=0` cả hai |
| `md5sum input.pcap` | `b4e25b3a67a7876860dd9e27ee612c36` |
| `md5sum input-multiline.pcap` | `be54363d76702fa1484bd2420eb37406` |

## 1. Kịch bản

TC-09 ghi chiều **client → server** (các lệnh); TC-10 ghi chiều **server → client** (các reply) của
cùng một kịch bản. Hai file bằng chứng, hai chiều, không trùng một packet nào.

`input.pcap` — 9 reply của aiosmtpd:

| # | Reply | Ca nó kiểm |
|---|---|---|
| 1 | `220 victim.lab Python SMTP 1.4.6` | banner, mã 2xx (REQ-9.2) |
| 2–4 | `250-victim.lab` · `250-8BITMIME` · `250 HELP` | reply nhiều dòng của EHLO — **mỗi dòng một segment**, xem §6 |
| 5–7 | `250 OK` ×3 | reply cho `NOOP`, `mail from:`, `RCPT TO:` |
| 8 | `500 Error: command "FOOBAR" not recognized` | mã **5xx**: lỗi cú pháp phía client |
| 9 | `221 Bye` | mã 2xx đóng phiên |

`input-multiline.pcap` — **một** packet, mang trọn reply nhiều dòng trong một segment. Đây là ca
REQ-9.3 mà traffic của aiosmtpd **không** tạo ra được (§6 giải thích). Server dùng cho file này là một
socket python một-lần-ghi chạy trong container `victim`, nghe port **2525**, gửi **đúng cùng 3 dòng**
mà aiosmtpd đã gửi ở packet 2–4 của file trên:

```
250-victim.lab\r\n250-8BITMIME\r\n250 HELP\r\n
```

Cùng bytes, cùng thứ tự, cùng giao thức — **chỉ khác cách ghi**. Port 2525 là phần thưởng kèm theo:
nó chứng minh REQ-11.3 (nhận diện SMTP trên port không chuẩn) bằng traffic thật.

## 2. Lệnh tái hiện

**File 1 — chiều reply của phiên SMTP thật:**

```sh
TC=TEST/TC-10_smtp-response
docker compose exec -T attacker tcpdump -i eth0 -U -c 9 -w - \
    'src host 10.20.0.10 and tcp src port 25 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' \
    > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker sh -c '(printf "EHLO attacker.lab\r\n";                  sleep 1; \
                                        printf "NOOP\r\n";                               sleep 1; \
                                        printf "mail from:<attacker@attacker.lab>\r\n";  sleep 1; \
                                        printf "RCPT TO:<admin@victim.lab>\r\n";         sleep 1; \
                                        printf "FOOBAR baz\r\n";                         sleep 1; \
                                        printf "QUIT\r\n";                               sleep 1) \
                                       | nc -w 3 10.20.0.10 25' > /dev/null
wait $CAP
```

Bộ lọc chỉ khác TC-09 ở **chiều** (`src host 10.20.0.10 and tcp src port 25`); ba phép tính trong
ngoặc và lý do dùng `-c` giải thích ở `TC-09/README.md` §2. `-c 9` = 1 banner + 3 dòng EHLO + 3 × `250
OK` + 1 × `500` + 1 × `221`.

**File 2 — reply nhiều dòng trong một segment:**

```sh
docker compose exec -T victim python3 -c "
import socket
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 2525)); srv.listen(1)
conn, _ = srv.accept()
conn.sendall(b'250-victim.lab\r\n250-8BITMIME\r\n250 HELP\r\n')
conn.close(); srv.close()
" &
SRV=$!
sleep 2
docker compose exec -T attacker tcpdump -i eth0 -U -c 1 -w - \
    'src host 10.20.0.10 and tcp src port 2525 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' \
    > $TC/input-multiline.pcap &
CAP=$!
sleep 2
docker compose exec -T attacker nc -w 2 10.20.0.10 2525 < /dev/null
wait $CAP; wait $SRV
```

`sendall()` **một lần** là toàn bộ điểm khác biệt: kernel gộp cả 3 dòng vào một segment.

**Chạy cả hai file:**

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | grep -v '^ *Container ' | tee $TC/run.log
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input-multiline.pcap -o $TC/output-multiline.jsonl 2>&1 \
    | grep -v '^ *Container ' | tee -a $TC/run.log
```

## 3. Kết quả mong đợi

Điều kiện dừng của T9.4: thư mục đủ tệp; có dòng `"status_code":220`; và **một** dòng response nhiều
dòng có `lines` ≥ 2 phần tử.

## 4. Kết quả thực tế

```sh
$ grep -o '"status_code":[0-9]*' TEST/TC-10_smtp-response/output.jsonl
"status_code":220
"status_code":250
"status_code":250
"status_code":250
"status_code":250
"status_code":250
"status_code":250
"status_code":500
"status_code":221
$ grep -o '"lines":\[[^]]*\]' TEST/TC-10_smtp-response/output-multiline.jsonl
"lines":["victim.lab","8BITMIME","HELP"]
$ grep -o '"detect_method":"[^"]*"' TEST/TC-10_smtp-response/output-multiline.jsonl
"detect_method":"payload"
$ cat TEST/TC-10_smtp-response/run.log
processed=9 unknown=0 malformed=0
processed=1 unknown=0 malformed=0
```

`"status_code":220` có ở packet 1 của file thứ nhất; `lines` **3 phần tử** với **một** `status_code`
duy nhất có ở file thứ hai → **đạt** cả hai phần.

Chín event của `input.pcap` (`kind` = `response`, `command`/`argument` = `null`, `status` = `ok`,
`errors` = `[]` ở cả chín):

| # | `status_code` | `lines` |
|---|---|---|
| 1 | 220 | `["victim.lab Python SMTP 1.4.6"]` |
| 2 | 250 | `["victim.lab"]` |
| 3 | 250 | `["8BITMIME"]` |
| 4 | 250 | `["HELP"]` |
| 5–7 | 250 | `["OK"]` |
| 8 | **500** | `["Error: command \"FOOBAR\" not recognized"]` |
| 9 | 221 | `["Bye"]` |

## 5. Đối chiếu từng byte với payload

Packet 1 của `input.pcap` (34 byte):

```
32 32 30 20 76 69 63 74 69 6d 2e 6c 61 62 20 50 79 74 68 6f 6e 20 53 4d 54 50 20 31 2e 34 2e 36 0d 0a
 2  2  0 SP  v  i  c  t  i  m  .  l  a  b SP  P  y  t  h  o  n SP  S  M  T  P SP  1  .  4  .  6 CR LF
|<- mã ->|^ phân cách                                                                         |<-CRLF->|
```

- **`32 32 30` là ba ký tự `"220"`, không phải số 220.** Mã trả lời đi trên dây dưới dạng **văn bản
  thập phân**, nên parser phải `int()` nó lại. Event ghi `220` là số (REQ-9.2), vì luật phát hiện so
  theo khoảng (4xx, 5xx) — mà so chuỗi thì `"99" > "500"`.
- **Byte thứ 4 (`20` = dấu cách) là trường PHÂN CÁCH, không phải dữ liệu.** Dấu cách = "đây là dòng
  CUỐI của reply"; `2d` (`-`) = "còn dòng nữa" (RFC 5321 §4.2.1). Packet 2 và 3 có `2d` ở đúng vị trí
  đó, packet 4 có `20` → đó là cách biết reply EHLO kết thúc ở packet 4.
- **`lines` không chứa 4 byte đầu.** Mã đã nằm ở `status_code`, phân cách là siêu dữ liệu — nên
  `lines[0]` bắt đầu từ byte thứ 5 (`victim.lab Python SMTP 1.4.6`).

Packet duy nhất của `input-multiline.pcap` (40 byte, cùng 3 dòng nhưng một segment):

```
32 35 30 2d 76 69 63 74 69 6d 2e 6c 61 62 0d 0a | 32 35 30 2d 38 42 49 54 4d 49 4d 45 0d 0a | 32 35 30 20 48 45 4c 50 0d 0a
"250" "-"  v  i  c  t  i  m  .  l  a  b  CR LF   "250" "-" 8  B  I  T  M  I  M  E  CR LF      "250" " " H  E  L  P  CR LF
        ^ con dong nua                              ^ con dong nua                                ^ DONG CUOI
```

Ba mã đều là `250` → `status_code` = 250 **một lần**, `lines` = 3 phần tử. Đúng REQ-9.3: "toàn bộ các
dòng và **một** status code chung".

## 6. Vì sao cần hai file: reply nhiều dòng là tính chất của CÁCH GHI, không phải của giao thức

Đây là quan sát quan trọng nhất của test case này, và nó đến từ dữ liệu thật chứ không từ suy đoán.

**aiosmtpd ghi mỗi dòng của reply EHLO bằng một lời gọi gửi riêng.** Hệ quả trên dây: 3 segment, và
theo giả định A2 (parse từng packet, không ghép luồng TCP) → **3 event**, mỗi event `lines` chỉ có
1 phần tử:

```
packet 2: status_code=250  lines=["victim.lab"]     <- "-" : con dong nua
packet 3: status_code=250  lines=["8BITMIME"]       <- "-" : con dong nua
packet 4: status_code=250  lines=["HELP"]           <- " " : dong cuoi
```

Không có event nào có `lines` ≥ 2. Nói cách khác: **điều kiện dừng của T9.4 không thể đạt được bằng
traffic của server này** — không phải vì parser sai, mà vì "nhiều dòng trong một `lines`" đòi nhiều
dòng nằm trong **một segment**, và điều đó do **cách server gọi `send()`** quyết định.

Vì vậy file thứ hai dùng một server gửi trọn reply bằng **một** `sendall()`. Cùng 40 byte, cùng thứ
tự, cùng 3 mã `250` — chỉ khác một chi tiết mà không nằm trong giao thức, và kết quả đổi hẳn:
`lines` = 3.

Ba điều rút ra, đều là câu trả lời sẵn cho vấn đáp:

1. **Ranh giới segment là dữ liệu đầu vào của IDS, không phải chi tiết bỏ qua được.** Cùng một reply
   SMTP có thể cho 1 event hoặc 3 event tuỳ bên gửi. Luật phát hiện viết trên `lines` phải chịu được
   cả hai — hoặc phải chạy sau một tầng ghép luồng.
2. **Phải ghép luồng TCP thì "một reply = một đơn vị" mới đúng.** Đó chính là việc A2 loại khỏi bài 1
   và là việc các IDS thật làm (Suricata/Zeek đều parse tầng ứng dụng **trên stream đã ghép**, không
   trên từng packet).
3. **Chiều ngược lại cũng đúng:** nhiều reply có thể nằm trong **một** segment. RFC 2920 (PIPELINING)
   cho phép server gộp reply của nhiều lệnh, kể cả **khác mã** (`250 OK` `250 OK` `550 no such user`).
   Đây là lý do chữ ký nhận diện ở T9.2b **không** đòi "mọi dòng cùng một mã" — đòi thì sẽ bỏ sót
   traffic hợp lệ đó (design ADR-5, `tests/test_detector.py::test_a_pipelined_reply_batch_is_still_smtp`).

## 7. Nhận xét

- **`detect_method` khác nhau ở hai file và đó là điểm cần chỉ ra khi vấn đáp:** file 1 là
  `"port+payload"` (port 25 khớp Phụ lục C **và** payload khớp chữ ký), file 2 là `"payload"` (port
  2525 không có trong registry, một mình payload gánh kết luận) → REQ-11.3. Cùng một chữ ký, hai đường
  đi tới cùng một kết luận.
- **Mã `500` ở packet 8 là reply cho lệnh `FOOBAR` mà TC-09 ghi ở chiều ngược.** Hai file bằng chứng
  của hai test case khớp nhau: IDS gán `UNKNOWN` cho lệnh đó (TC-09 packet 5) trong khi server trả
  `500` — hai cách nói cùng một việc, từ hai phía. Đặt cạnh nhau là cách kiểm chứng rằng bộ nhận diện
  không "tự tin hơn" server thật.
- **Không event nào `malformed`.** Ca `malformed` của SMTP (mã không đồng nhất trong một reply, CR/LF
  lẻ, byte > 0x7F) không xuất hiện được trên traffic của một server đúng chuẩn, nên chúng được kiểm
  bằng payload dựng tay trong `tests/test_smtp.py` — cùng lý lẽ đã dùng cho `tests/test_dns.py`
  (`TC-07/README.md` §6).
- **`status_code` là số, `lines` là danh sách chuỗi — không có khoá nào cho dấu phân cách `-`/` `.**
  Tập khoá của `app` đã chốt ở design §5.4 (A.7) và I-2 buộc mọi event dùng cùng một tập khoá, nên
  không tự thêm khoá giữa bài. Dấu phân cách vẫn đọc lại được từ `tcp.payload_b64`, và ý nghĩa của nó
  ("reply đã hết chưa") là tính chất của **stream**, mà stream thì bài 1 không dựng (A2).
