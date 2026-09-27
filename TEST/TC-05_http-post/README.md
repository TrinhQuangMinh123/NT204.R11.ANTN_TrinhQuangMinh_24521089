# TC-05 — HTTP POST

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-7.2 (body và `body_len`), I-4 (base64 giải ngược đúng), I-3 (một event = một dòng JSON) |
| Task | T7.3 · Phase 7 |
| Ngày ghi | 2026-09-27 |
| Traffic | `POST /submit` với body 30 byte, **trong body có một dòng trống (`CRLFCRLF`)** |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0` |
| `md5sum input.pcap` | `ba607b05f3b87e75713b1f4be86925f9` |

## 1. Kịch bản

Body gửi lên **đúng 30 byte**:

```
user=admin&pass=1234\r\n\r\nlast=1
```

Chuỗi này không phải ngẫu nhiên. Nó chứa đúng **`CRLFCRLF`** — dấu phân cách mà parser dùng để biết
phần header kết thúc ở đâu. Nhờ vậy test case kiểm được ba điều cùng lúc:

1. **Parser lấy lần xuất hiện ĐẦU TIÊN của `CRLFCRLF`** (`payload.find`, không phải `rfind`): nếu
   lấy lần cuối thì ranh giới header/body nhảy vào giữa body, `headers` mất 0 dòng nhưng `body_len`
   sẽ ra `6` thay vì `30`.
2. **base64 giữ được byte điều khiển** (I-4): `\r` và `\n` trong body không thể ghi trực tiếp vào
   JSON, nên `body_b64` là cách duy nhất để bằng chứng còn nguyên bytes trên dây.
3. **Một event vẫn là một dòng** (I-3): body chứa `\n` thật mà `output.jsonl` vẫn có đúng 10 dòng —
   `json.dumps` escape chúng thành `\r\n` hai ký tự.

Endpoint là `location /submit` của nginx (`return 200`), vì nginx trả **405** cho POST vào file tĩnh.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-05_http-post
docker compose exec -T attacker tcpdump -i eth0 -U -c 10 -w - \
    'tcp and host 10.20.0.10 and port 80' > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker sh -c \
    "printf 'user=admin&pass=1234\r\n\r\nlast=1' | curl -s -o /dev/null --data-binary @- http://10.20.0.10/submit"
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

Dùng **`--data-binary @-`** chứ không phải `-d`: `-d` bỏ hết ký tự xuống dòng trong dữ liệu đọc từ
stdin, tức nó sẽ xoá đúng phần `CRLFCRLF` mà test case này cần. `printf` (không phải `echo`) vì
`printf` hiểu `\r` và không thêm `\n` ở cuối.

`-c 10` để tcpdump tự thoát sau đúng 10 packet — lý do ở `TC-02/README.md` §2.

## 3. Kết quả mong đợi

Điều kiện dừng của T7.3: dòng `"method":"POST"` có `body_len` > 0, và giải base64 `body_b64` ra
**đúng** chuỗi đã gửi (`user=admin&pass=1234\r\n\r\nlast=1`, 30 byte).

## 4. Kết quả thực tế

```sh
$ grep -o '"body_len":[0-9]*' TEST/TC-05_http-post/output.jsonl | sort | uniq -c
      1 "body_len":30
      1 "body_len":9
$ grep -o '"body_b64":"[^"]*"' TEST/TC-05_http-post/output.jsonl
"body_b64":"dXNlcj1hZG1pbiZwYXNzPTEyMzQNCg0KbGFzdD0x"
"body_b64":"cmVjZWl2ZWQK"
$ cat TEST/TC-05_http-post/run.log
processed=10 unknown=0 malformed=0
```

Giải mã ngược:

```python
>>> base64.b64decode("dXNlcj1hZG1pbiZwYXNzPTEyMzQNCg0KbGFzdD0x")
b'user=admin&pass=1234\r\n\r\nlast=1'      # 30 byte, khớp từng byte với chuỗi đã gửi
>>> base64.b64decode("cmVjZWl2ZWQK")
b'received\n'                              # body của response, 9 byte
```

→ **đạt**. Khoá `app` của packet 4:

```json
{"kind": "request", "method": "POST", "uri": "/submit", "version": "HTTP/1.1",
 "status_code": null, "reason": null,
 "headers": [["Host", "10.20.0.10"], ["User-Agent", "curl/8.14.1"], ["Accept", "*/*"],
             ["Content-Length", "30"], ["Content-Type", "application/x-www-form-urlencoded"]],
 "body_len": 30, "body_b64": "dXNlcj1hZG1pbiZwYXNzPTEyMzQNCg0KbGFzdD0x", "incomplete": false}
```

## 5. Hai con số độc lập: `body_len` và `Content-Length`

| Nguồn | Giá trị | Ai tạo ra |
|---|---|---|
| `app.body_len` | `30` | **parser đếm** số byte body có thật trong packet |
| `headers` → `Content-Length` | `"30"` | **bên gửi khai** |

Ở đây hai số bằng nhau vì body nhỏ, đi trọn trong một segment. Chúng được ghi **riêng** (REQ-7.2) vì
trong thực tế chúng lệch nhau ở hai tình huống khác hẳn nhau:

- body trải trên nhiều segment → `body_len` < `Content-Length`: **bình thường**;
- `Content-Length` khai nhỏ hơn số byte thật, hoặc có hai dòng `Content-Length` → dấu hiệu
  **request smuggling**.

Nếu parser lấy `Content-Length` làm `body_len` thì cả hai tình huống trên đều biến mất khỏi event, và
luật phát hiện ở bài sau không còn gì để so sánh.

## 6. Toàn bộ 10 packet

| # | Chiều | `flags` | `payload_len` | `app_proto` | `app` |
|---|---|---|---|---|---|
| 1–3 | handshake | `SYN` / `SYN,ACK` / `ACK` | 0 | `null` | `null` |
| 4 | attacker → victim | `["PSH","ACK"]` | 180 | `HTTP` | request `POST /submit`, 5 header, `body_len=30` |
| 5 | victim → attacker | `["ACK"]` | 0 | `null` | `null` |
| 6 | victim → attacker | `["PSH","ACK"]` | 163 | `HTTP` | response `200 OK`, 5 header, `body_len=9` |
| 7 | attacker → victim | `["ACK"]` | 0 | `null` | `null` |
| 8–10 | đóng kết nối | `FIN,ACK` / `FIN,ACK` / `ACK` | 0 | `null` | `null` |

`payload_len` (180) = độ dài request line + header + `CRLFCRLF` + body (30). Chênh 150 byte so với
`body_len` chính là phần header — `body_len` chỉ đếm phần **sau** dòng trống.

## 7. Nhận xét

- `Content-Type: application/octet-stream` trong response là của nginx `return 200` (nó không đoán
  kiểu cho chuỗi trả về cứng). Không ảnh hưởng gì đến parser: parser không đọc `Content-Type`.
- Body có dòng trống nhưng `incomplete=false`: cờ này chỉ nói **"chưa thấy hết phần header"**, không
  liên quan tới việc body đã đủ hay chưa. Đúng REQ-7.4 — bài 1 không ghép segment (A2), nên không có
  cách nào biết body đã đủ hay chưa ngoài việc so với `Content-Length`, mà đó là việc của luật phát
  hiện.
- Cả phiên có `malformed=0`: body chứa `CRLFCRLF` là dữ liệu hoàn toàn hợp lệ, không phải lỗi. Parser
  chỉ báo lỗi khi **cú pháp phần header** sai (V6.2).
