# TC-09 — SMTP command

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-9.1 (tên lệnh + tham số, ít nhất HELO/EHLO, MAIL FROM, RCPT TO), REQ-10.2 (payload quyết định kết quả nhận diện) |
| Task | T9.3 · Phase 9 |
| Ngày ghi | 2026-09-27 |
| Traffic | một phiên SMTP gõ tay bằng `nc` tới `10.20.0.10:25` (aiosmtpd) |
| Kết quả | 6 packet, `processed=6 unknown=0 malformed=0` |
| `md5sum input.pcap` | `19cf63eef6ddedb24696c83778549b1e` |

## 1. Kịch bản

Sáu lệnh gửi lần lượt, mỗi lệnh cách nhau 1 giây nên mỗi lệnh nằm trong **một segment TCP riêng**.
Bốn lệnh đầu là bốn ca REQ-9.1 đòi, hai lệnh sau là hai ca biên cố tình thêm:

| # | Gửi đi | Ca nó kiểm |
|---|---|---|
| 1 | `EHLO attacker.lab` | lệnh có tham số (REQ-9.1) |
| 2 | `NOOP` | lệnh **không** tham số → `argument` phải là `null`, không phải `""` |
| 3 | `mail from:<attacker@attacker.lab>` | **chữ thường** → chuẩn hoá tên lệnh (RFC 5321 §2.4) |
| 4 | `RCPT TO:<admin@victim.lab>` | tên lệnh **chứa dấu cách** (REQ-9.1) |
| 5 | `FOOBAR baz` | port 25 khớp nhưng payload **không** khớp chữ ký → `UNKNOWN` (REQ-10.2) |
| 6 | `QUIT` | lệnh không tham số, kết thúc phiên đúng cách |

Lệnh 3 viết chữ thường có chủ đích: nó chứng minh cùng một lúc hai điều ngược nhau — event ghi
`"command":"MAIL FROM"` (chuẩn hoá để luật phát hiện chỉ phải viết một cách), mà `lines[0]` vẫn giữ
`"mail from:<attacker@attacker.lab>"` nguyên văn (không mất bằng chứng). Nó còn cho thấy **server thật
cũng hiểu như vậy**: aiosmtpd trả `250 OK` cho dòng chữ thường đó.

Lệnh 5 là ca ngược của REQ-10.2: cùng port 25, cùng phiên, cùng hình dạng "một dòng chữ kết thúc bằng
CRLF" — chỉ khác ở chỗ `FOOBAR` không có trong 10 lệnh của Phụ lục C. Server đáp
`500 Error: command "FOOBAR" not recognized` (xem TC-10), và IDS thì ghi `app_proto:"UNKNOWN"`.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-09_smtp-command
docker compose exec -T attacker tcpdump -i eth0 -U -c 6 -w - \
    'src host 10.10.0.10 and tcp dst port 25 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' \
    > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker sh -c '(printf "EHLO attacker.lab\r\n";                  sleep 1; \
                                        printf "NOOP\r\n";                               sleep 1; \
                                        printf "mail from:<attacker@attacker.lab>\r\n";  sleep 1; \
                                        printf "RCPT TO:<admin@victim.lab>\r\n";         sleep 1; \
                                        printf "FOOBAR baz\r\n";                         sleep 1; \
                                        printf "QUIT\r\n";                               sleep 1) \
                                       | nc -w 3 10.20.0.10 25'
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | grep -v '^ *Container ' | tee $TC/run.log
```

Ba chi tiết của lệnh bắt gói:

- **Bộ lọc chỉ lấy packet CÓ payload, một chiều.** Ba phép tính trong ngoặc chính là hai phép trừ mà
  `parse_ipv4` và `parse_tcp` làm: `ip[2:2]` là `total_length`, `(ip[0]&0xf)<<2` là `ihl*4`,
  `(tcp[12]&0xf0)>>2` là `data_offset*4` — hiệu của chúng là số byte payload. `!= 0` nên SYN, ACK
  trống và FIN bị loại. Nhờ vậy **6 lệnh = đúng 6 packet**, `-c 6` tất định, và file bằng chứng không
  lẫn gói của TC-01 (handshake) hay của TC-10 (chiều reply).
- **`-c 6`** — tcpdump tự thoát, không để lại tiến trình nào giữ fd vào file bằng chứng. Không dùng
  `timeout` trong container: trên máy WSL2 này `timeout` không bắn tín hiệu (lý do đầy đủ ở
  `TC-02/README.md` §2).
- **`printf` chứ không gõ tay vào `nc`.** `printf` viết đúng `\r\n` (CRLF) mà RFC 5321 §2.3.8 đòi;
  gõ tay trong terminal chỉ gửi `\n` trần → parser sẽ báo lỗi `smtp line ending is not crlf`
  (có test riêng: `tests/test_smtp.py::test_bare_lf_in_a_command_is_reported`). Mỗi `printf` cách nhau
  `sleep 1` nên mọi byte trước đó đã được ACK → Nagle không ghép hai lệnh vào một segment.

`grep -v '^ *Container '` bỏ dòng tiến trình của Compose (chứa id sinh ngẫu nhiên, sẽ làm bằng chứng
không lặp lại được).

## 3. Kết quả mong đợi

Điều kiện dừng của T9.3: `TEST/TC-09_smtp-command/` đủ 4 tệp; output có các dòng `"command":"EHLO"`,
`"command":"MAIL FROM"`, `"command":"RCPT TO"`.

## 4. Kết quả thực tế

```sh
$ grep -o '"command":"[^"]*"' TEST/TC-09_smtp-command/output.jsonl
"command":"EHLO"
"command":"NOOP"
"command":"MAIL FROM"
"command":"RCPT TO"
"command":"QUIT"
$ grep -o '"app_proto":"[^"]*","detect_method":[^,]*' TEST/TC-09_smtp-command/output.jsonl
"app_proto":"SMTP","detect_method":"port+payload"
"app_proto":"SMTP","detect_method":"port+payload"
"app_proto":"SMTP","detect_method":"port+payload"
"app_proto":"SMTP","detect_method":"port+payload"
"app_proto":"UNKNOWN","detect_method":null
"app_proto":"SMTP","detect_method":"port+payload"
$ cat TEST/TC-09_smtp-command/run.log
processed=6 unknown=0 malformed=0
```

Cả ba lệnh mà điều kiện dừng đòi đều có mặt → **đạt**.

Khoá `app` của sáu packet (`status` = `ok`, `errors` = `[]` ở cả sáu):

| # | payload trên dây | `kind` | `command` | `argument` | `lines` |
|---|---|---|---|---|---|
| 1 | `EHLO attacker.lab` | command | `EHLO` | `attacker.lab` | `["EHLO attacker.lab"]` |
| 2 | `NOOP` | command | `NOOP` | `null` | `["NOOP"]` |
| 3 | `mail from:<attacker@attacker.lab>` | command | `MAIL FROM` | `<attacker@attacker.lab>` | `["mail from:<attacker@attacker.lab>"]` |
| 4 | `RCPT TO:<admin@victim.lab>` | command | `RCPT TO` | `<admin@victim.lab>` | `["RCPT TO:<admin@victim.lab>"]` |
| 5 | `FOOBAR baz` | — | — | — | `app` là `null` |
| 6 | `QUIT` | command | `QUIT` | `null` | `["QUIT"]` |

## 5. Đối chiếu từng byte với payload

Packet 4, toàn bộ payload TCP (từ `tcp.payload_b64`, 28 byte):

```
52 43 50 54 20 54 4f 3a 3c 61 64 6d 69 6e 40 76 69 63 74 69 6d 2e 6c 61 62 3e 0d 0a
 R  C  P  T  SP  T  O  :  <  a  d  m  i  n  @  v  i  c  t  i  m  .  l  a  b  > CR LF
|<------ tên lệnh: 8 byte -------->|<-------- argument: 18 byte --------->|<-CRLF->|
```

- **Tên lệnh dài 8 byte và CHỨA một dấu cách.** `line.split(" ")` sẽ cắt ở byte thứ 5 và cho
  `command="RCPT"`, `argument="TO:<admin@victim.lab>"` — sai cả hai trường. Nên parser cắt theo **độ
  dài chữ ký** lấy từ bảng `COMMANDS`: thấy payload mở đầu bằng `RCPT TO:` thì bỏ đúng 8 byte đó.
- **Dấu `:` thuộc chữ ký, không thuộc tham số.** Nhờ vậy `argument` bắt đầu ngay ở `<` — đúng dạng
  reverse-path/forward-path của RFC 5321 §4.1.2, là thứ luật phát hiện sẽ đem đi so (relay hở, địa
  chỉ người nhận lạ).
- **`0d 0a` ở cuối là dấu kết thúc dòng, không phải dữ liệu.** `argument` không chứa nó vì phần này
  được cắt ra ở bước chia dòng, trước khi tách tên lệnh.
- **Ba con số của event khớp nhau:** `ipv4.total_length` 80 − `ihl`(5)×4 − `data_offset`(8)×4 = 28 =
  `tcp.payload_len` = độ dài payload ở trên. Cùng hai phép trừ mà bộ lọc tcpdump ở §2 dùng.

Packet 3, 10 byte đầu — ca chữ thường:

```
6d 61 69 6c 20 66 72 6f 6d 3a
 m  a  i  l  SP  f  r  o  m  :
```

Trên dây là `6d` (`m`), trong event là `"MAIL FROM"`. Phép chuẩn hoá chỉ là `bytes.upper()` trên
**phần tên lệnh**; tham số và `lines[0]` giữ nguyên byte gốc.

## 6. Vì sao packet 5 là `UNKNOWN` mà không phải `malformed`

`FOOBAR baz\r\n` đi tới port 25 nên SMTP **được thử đầu tiên** (ADR-5), nhưng `matches_smtp()` trả
`False`: `FOOBAR` không có trong 10 lệnh của Phụ lục C, và 3 byte đầu `F`, `O`, `O` không phải chữ số
nên chữ ký reply cũng không khớp. Không giao thức nào còn lại ở TCP → `app_proto:"UNKNOWN"`,
`detect_method:null`, `app:null`.

Đây **không** phải lỗi, nên `errors` rỗng và `status` vẫn `ok` (ADR-14):

- `UNKNOWN` = "có dữ liệu nhưng bài này chưa có chữ ký nào nhận ra nó" — hoàn toàn bình thường, một
  phiên SMTP thật còn có `HELP`, `VRFY`, `EXPN`, và cả nội dung thư sau lệnh `DATA`.
- `malformed` = "đã nhận ra giao thức nhưng dữ liệu của nó sai" — phải có một parser chỉ ra được sai
  ở đâu.

Nếu `parse_smtp` được gọi **trực tiếp** trên `FOOBAR baz\r\n` thì nó trả về `error` ("neither a reply
line nor a command in the known set"); qua pipeline thì ca đó không tới được vì detector gác trước.
Ranh giới này giống hệt ranh giới đã ghi ở V8.1 cho DNS: parser chỉ nói về dữ liệu **sau khi** giao
thức đã được nhận diện.

## 7. Nhận xét

- **Không có gói nào ngoài 6 lệnh.** Handshake, ACK trống và FIN của cùng phiên đó bị bộ lọc payload
  loại ra — chúng đã có bằng chứng riêng ở TC-01 (`app_proto:null`, REQ-15.4). Một file bằng chứng chỉ
  nên chứa thứ nó muốn chứng minh.
- **`detect_method="port+payload"` ở cả 5 packet SMTP:** port 25 đưa SMTP vào nhóm thử đầu, và chữ ký
  lệnh khớp. Ca `"payload"` (SMTP trên port lạ, REQ-11.3) kiểm bằng `tests/test_detector.py` vì lab chỉ
  chạy aiosmtpd ở port 25; dựng thêm một port nữa chỉ để đổi một con số trong event là không đáng.
- **`lines` có đúng một phần tử ở cả 5 packet SMTP.** SMTP chạy lock-step (gửi một lệnh, chờ reply),
  nên nhiều lệnh trong một segment chỉ xảy ra khi client dùng pipelining (RFC 2920) — ca đó kiểm bằng
  `tests/test_smtp.py::test_pipelined_commands_keep_every_line`, không bắt được bằng `nc` gõ tay.
- **`argument` của `NOOP`/`QUIT` là `null`, không phải `""`.** Hai giá trị nói hai việc khác nhau:
  `null` = trên dây không có chỗ cho tham số; `""` = có dấu cách rồi hết dòng (`HELO \r\n`) — một lỗi
  cú pháp của client mà luật phát hiện có thể quan tâm. Giữ hai giá trị riêng là giữ được sự khác biệt
  đó.
- **Giới hạn A2 nhìn thấy được ở đây:** mỗi event là một packet, nên không có chỗ nào trong output nói
  "phiên này đã MAIL FROM rồi mới RCPT TO". Ghép các lệnh của một phiên thành một trạng thái là việc
  của module bài sau (feature extraction theo flow), và nó làm được vì mọi event đã có đủ 5-tuple.
