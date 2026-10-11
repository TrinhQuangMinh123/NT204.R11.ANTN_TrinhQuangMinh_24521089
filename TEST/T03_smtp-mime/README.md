# T03 — SMTP Base64 / Quoted-Printable

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-23.1–23.3 (giải Base64/QP ở mức packet + `decode_status`), REQ-40.2 (gom thư nhiều packet ở mức flow), ADR-26, Phụ lục K T03 |
| Task | T5.6 · Phase 5 (bài 2) |
| Ngày ghi | 2026-10-11 |
| Traffic | hai phiên SMTP **đầy đủ** (có `DATA` và reply `354`) tới `aiosmtpd` của `victim` |
| Kết quả | `single`: 26 packet · `multi`: 39 packet · cả hai `malformed=0`, exit 0 |
| `md5sum input-single.pcap` | `8c0187a2202c545d0cb1bc827eabfa3f` |
| `md5sum input-multi.pcap` | `7c9fdfb374ddfbae565de0726a8ab0d5` |

## 1. Kịch bản

Hai ca cố tình khác nhau ở **chỗ thư nằm trên dây**, vì chính chỗ đó quyết định tầng nào giải mã được:

| | `input-single.pcap` | `input-multi.pcap` |
|---|---|---|
| Cách gửi | client **pipelining**: toàn bộ phiên trong **một** lần `write` → một segment TCP | phiên đúng chuẩn: chờ reply từng bước, thân thư chia **ba** segment |
| Encoding | Base64 | Quoted-Printable (`=C3=A0` → `à`) |
| Thư nằm cùng packet với | lệnh `DATA` | không gì cả (đi sau reply `354`) |
| Kết quả giải mã ở | **event**: `decode.mime` | **flow record**: `mails[0]`, `rule` = `F8` |

Ca `multi` còn chứa một dòng thân thư bắt đầu bằng dấu chấm, gửi trên dây thành `..dong bat dau bang
dau cham` — để kiểm việc **gỡ dot-stuffing** (RFC 5321 §4.5.2).

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

# --- ca 1: cả phiên trong một lần write ---
docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 25" > /tmp/cap.pcap 2>/dev/null &
  TD=$!; sleep 2
  printf "EHLO attacker.lab\r\nMAIL FROM:<attacker@attacker.lab>\r\nRCPT TO:<admin@victim.lab>\r\nDATA\r\nSubject: single packet mail\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8gZnJvbSBUMDMgc2luZ2xlIHBhY2tldCBtYWls\r\n.\r\nQUIT\r\n" \
    | nc -w 3 10.20.0.10 25 > /tmp/smtp.out
  sleep 2; kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T03_smtp-mime/input-single.pcap

# --- ca 2: chờ reply, thân thư ba segment ---
docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 25" > /tmp/cap.pcap 2>/dev/null &
  TD=$!; sleep 2
  { printf "EHLO attacker.lab\r\n";                        sleep 1
    printf "MAIL FROM:<attacker@attacker.lab>\r\n";        sleep 1
    printf "RCPT TO:<admin@victim.lab>\r\n";               sleep 1
    printf "DATA\r\n";                                     sleep 1
    printf "Subject: multi packet mail\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nXin ch=C3=A0o,\r\n"; sleep 1
    printf "thu nay trai tren nhieu packet.\r\n";          sleep 1
    printf "..dong bat dau bang dau cham";                 sleep 1
    printf "\r\n.\r\n";                                    sleep 1
    printf "QUIT\r\n";                                     sleep 1
  } | nc -w 3 10.20.0.10 25 > /tmp/smtp.out
  sleep 2; kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T03_smtp-mime/input-multi.pcap

# --- chạy pipeline cho cả hai ca ---
export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T03_smtp-mime
: > $TC/run.log
for v in single multi; do
  docker compose run --rm idps-offline python main.py --pcap $TC/input-$v.pcap \
      -o $TC/output-$v.jsonl --flow-output $TC/flows-$v.jsonl > /tmp/raw.log 2>&1
  code=$?
  echo "== $v ==" >> $TC/run.log
  grep -v '^ *Container ' /tmp/raw.log >> $TC/run.log
  echo "exit=$code" >> $TC/run.log
done
```

`sleep 1` giữa các `printf` là phần **bắt buộc** của ca `multi`: nó vừa cho reply `354` kịp tới trước
thân thư, vừa buộc mỗi `printf` thành một segment TCP riêng (không có nó thì shell gộp hết và ca này
biến thành ca `single`).

## 3. Kết quả mong đợi

Điều kiện dừng T5.6: hai cặp `input-*.pcap`/`output-*.jsonl`/`flows-*.jsonl` + `run.log` + `README.md`;
chạy lại cả hai lệnh khớp từng byte; ca một packet có `decode.mime` với body **đã giải mã** +
`decode_status`; ca nhiều packet có nội dung thư đúng trong `mails` của **flow record**.

## 4. Kết quả thực tế

**Ca `single` — giải mã ở mức event (`output-single.jsonl`):**

```
decode.mime.status = "ok"
headers = [["Subject","single packet mail"], ["MIME-Version","1.0"],
           ["Content-Type","text/plain; charset=utf-8"], ["Content-Transfer-Encoding","base64"]]
parts[0].text   = "Hello from T03 single packet mail"
parts[0].status = "ok"
```
`flows-single.jsonl`: `mails` = `[]` (giải thích ở §5).

**Ca `multi` — giải mã ở mức flow (`flows-multi.jsonl`):**

```
mails[0].rule   = "F8"      mails[0].status = "ok"
headers = [["Subject","multi packet mail"], …, ["Content-Transfer-Encoding","quoted-printable"]]
parts[0].text   = "Xin chào,\r\nthu nay trai tren nhieu packet.\r\n.dong bat dau bang dau cham"
```
`output-multi.jsonl`: **không** event nào có `decode.mime` (giải thích ở §5).

Hai điều đọc ra ngay từ chuỗi `text`: `=C3=A0` đã thành `à` (Quoted-Printable, REQ-23.2) và `..dong`
đã thành `.dong` (dot-stuffing đã gỡ). Cả hai lần chạy: `malformed=0`, `decode_errors=0
preprocess_errors=0 flow_errors=0`, exit 0.

## 5. Vì sao chỗ đặt kết quả khác nhau giữa hai ca (REQ-23.5 vs REQ-40.2)

Đây là nội dung của V5.5, và nó là hệ quả của một tính chất của bài 1 — **không** phải lỗi:

- Detector của bài 1 nhận ra SMTP bằng chữ ký **ở đầu payload**: một lệnh (`EHLO`, `MAIL FROM`,
  `DATA`…) hoặc một reply số. Packet chứa **thân thư** (đi sau `354`) mở đầu bằng `Subject:` hay
  `Xin ch=C3=A0o` → không khớp chữ ký nào → `app_proto` = `UNKNOWN`. Mà F6 (`decode.mime`) chỉ áp khi
  `app_proto` = SMTP, nên ở ca `multi` **không** event nào có `decode.mime`. Muốn biết "packet này
  thuộc một phiên SMTP" thì phải có **flow context**, mà flow lại là stage *sau* Decoder — đúng lý do
  ADR-26 đặt việc gom thư ở mức flow.
- Ở ca `single`, thân thư đi **cùng segment** với lệnh `DATA`, nên packet đó *có* khớp chữ ký SMTP và
  F6 chạy được. Để F6 cho ra body đã giải mã, Decoder phải bỏ khung của giao thức trước khi parse
  MIME: bỏ dòng `DATA\r\n`, bỏ dấu kết thúc `\r\n.\r\n`, gỡ dot-stuffing (task T4.4). Không bỏ thì
  `email` coi dòng `DATA` là header sai → `headers` rỗng, body không được giải mã; còn dấu chấm cuối
  lọt vào chuỗi Base64 → `binascii` báo *"Excess data after padding"* và cả thư ra `invalid`.
- Ngược lại ở ca `single`, `mails` = `[]` là **đúng**: FlowTracker chỉ vào pha DATA khi thấy lệnh
  `DATA` **rồi** reply `354` từ chiều ngược (ADR-26). Lúc reply `354` tới thì thân thư đã đi qua từ
  trước, nên không còn byte nào để gom. Hai tầng vì vậy **bù** cho nhau: mỗi hình dạng traffic có ít
  nhất một tầng đọc được nội dung thư.

Việc dùng lại **đúng** `codecs.mime_decode` ở cả hai tầng (REQ-40.8) là lý do nội dung giải mã ra
giống nhau về cấu trúc (`headers`, `parts`, `status`) dù đường đi khác nhau — chỉ `rule` khác (`F6` ở
mức packet, `F8` ở mức flow) để đọc log là biết kết quả đến từ đâu.

## 6. Nhận xét

- **`nc` không phải MTA.** Phiên `single` là hành vi của **client pipelining**: gửi hết rồi mới đọc
  reply. RFC 2920 cho phép pipelining các lệnh, nhưng thân thư thì đúng chuẩn phải chờ `354` — nên ca
  `single` mô phỏng công cụ gửi thư hàng loạt / script tấn công, còn ca `multi` mô phỏng MTA thật.
  Một IDS phải đọc được **cả hai**.
- **Thư nằm trong `flows.jsonl` chứ không `output.jsonl` ở ca `multi`** — và đó là chỗ phải nhớ khi
  viết luật phát hiện mã độc đính kèm sau này: luật chạy trên event sẽ không bao giờ thấy thân thư.
- **`state` của flow là `CLOSED`** ở cả hai ca vì `QUIT` → `221` → hai chiều FIN; thống kê flow vẫn
  chốt đủ, việc gom thư không ảnh hưởng tới máy trạng thái TCP.
