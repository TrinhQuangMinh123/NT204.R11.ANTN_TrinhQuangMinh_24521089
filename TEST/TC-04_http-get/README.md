# TC-04 — HTTP GET

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-7.1 (method, URI, version, headers của request), REQ-10.4 (`detect_method`), REQ-15.4 (payload rỗng) |
| Task | T7.2 · Phase 7 |
| Ngày ghi | 2026-09-27 |
| Traffic | `curl 'http://10.20.0.10/index.html?file=../../etc/passwd&q=1'` với **hai header cùng tên** `X-Test` |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0` |
| `md5sum input.pcap` | `4e70d1832124ba690dd809379acd4e64` |

## 1. Kịch bản

Request được chọn để kiểm **ba tính chất mà luật phát hiện sau này dựa vào**, không chỉ để có một
dòng `"method":"GET"`:

1. **URI giữ nguyên văn** — query string chứa `../../etc/passwd`. Đây là hình dạng của một payload
   path traversal thật; nếu parser tự chuẩn hoá (bỏ `..`, giải `%2e`, cắt query) thì luật phát hiện
   sẽ soi một chuỗi **khác** chuỗi đã đi trên dây, và kẻ tấn công chỉ cần khai thác đúng khoảng
   chênh đó. Chuỗi này đặt ở **query** chứ không ở path vì `curl` tự chuẩn hoá dot-segment trong
   path trước khi gửi (RFC 3986) — muốn thấy `..` đi nguyên trên dây thì phải đặt sau dấu `?`.
2. **Header giữ thứ tự và giữ bản trùng** — gửi `X-Test: a` rồi `X-Test: b`. Nếu `headers` là dict
   thì bản sau ghi đè bản trước và bằng chứng biến mất; hai header cùng tên (điển hình là hai
   `Content-Length`) chính là hình dạng của request smuggling.
3. **Packet không có payload** — 8/10 packet của phiên là handshake/ack/đóng: chúng phải có
   `app_proto` là `null` và **không** có lỗi nào (REQ-15.4, kiểm chứng V7.2).

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-04_http-get
docker compose exec -T attacker tcpdump -i eth0 -U -c 10 -w - \
    'tcp and host 10.20.0.10 and port 80' > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker curl -s -o /dev/null \
    -H 'X-Test: a' -H 'X-Test: b' \
    'http://10.20.0.10/index.html?file=../../etc/passwd&q=1'
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

`-c 10` để tcpdump **tự thoát** sau đúng 10 packet (3 handshake + 2 data + 2 ack + 3 đóng): không có
tiến trình bắt gói nào sống sót giữ fd vào file bằng chứng — lý do đầy đủ ghi ở `TC-02/README.md` §2.
Dấu nháy đơn quanh URL là bắt buộc vì URL chứa `&` và `?`.

## 3. Kết quả mong đợi

Điều kiện dừng của T7.2: `grep -c '"method":"GET"' output.jsonl` ≥ 1, và dòng đó có `"uri":` và
`"headers":[[`.

## 4. Kết quả thực tế

```sh
$ grep -c '"method":"GET"' TEST/TC-04_http-get/output.jsonl
1
$ grep -o '"uri":"[^"]*"' TEST/TC-04_http-get/output.jsonl
"uri":"/index.html?file=../../etc/passwd&q=1"
$ grep -o '"headers":\[\[[^]]*\]' TEST/TC-04_http-get/output.jsonl | head -1
"headers":[["Host","10.20.0.10"]
$ cat TEST/TC-04_http-get/run.log
processed=10 unknown=0 malformed=0
```

→ **đạt**. Khoá `app` của packet 4 đầy đủ:

```json
{"kind": "request", "method": "GET",
 "uri": "/index.html?file=../../etc/passwd&q=1", "version": "HTTP/1.1",
 "status_code": null, "reason": null,
 "headers": [["Host", "10.20.0.10"], ["User-Agent", "curl/8.14.1"],
             ["Accept", "*/*"], ["X-Test", "a"], ["X-Test", "b"]],
 "body_len": 0, "body_b64": "", "incomplete": false}
```

`status_code` và `reason` là `null` vì đây là request — khoá vẫn **có mặt** (I-2: cùng một tập khoá
cho mọi event, module bài sau đọc `app["status_code"]` không cần `.get()`).

## 5. Đối chiếu với bytes trên dây

```python
>>> base64.b64decode(rows[3]["tcp"]["payload_b64"])
b'GET /index.html?file=../../etc/passwd&q=1 HTTP/1.1\r\nHost: 10.20.0.10\r\n'
b'User-Agent: curl/8.14.1\r\nAccept: */*\r\nX-Test: a\r\nX-Test: b\r\n\r\n'      # 132 byte
```

- `uri` trong event **bằng đúng** chuỗi giữa hai dấu cách của request line — không mất `?`, không
  giải `..`, không đổi `&`.
- 5 header trên dây → 5 cặp trong `headers`, **đúng thứ tự gửi**, `X-Test` xuất hiện **hai lần**.
- Payload kết thúc bằng `CRLFCRLF` và không có byte nào sau đó → `body_len=0`, `incomplete=false`.

## 6. Kiểm chứng V7.2 — packet không có payload

```sh
$ grep -c '"app_proto":null' TEST/TC-04_http-get/output.jsonl
8
$ grep -c '"errors":\[\]' TEST/TC-04_http-get/output.jsonl
10
```

8 packet không mang dữ liệu (1, 2, 3, 5, 7, 8, 9, 10) đều có `app_proto: null`, `detect_method:
null`, `app: null`, và **cả 10** packet có `errors` rỗng. Đúng REQ-15.4: payload rỗng **không** phải
lỗi và cũng **không** phải `"UNKNOWN"` — `detect()` trả `Detection(None, None)` ngay trước vòng lặp
vì mọi chữ ký đều cần ít nhất một byte.

## 7. Nhận xét

- `detect_method` của hai packet HTTP là `"port+payload"`: port 80 nằm trong `ports` của registry nên
  HTTP là ứng viên **được thử đầu tiên**, và payload khớp chữ ký nên kết quả được chấp nhận. Ca
  `"payload"` (port không chuẩn) là TC-13.
- Response ở packet 6 cũng được parse (`kind=response`, 200) — TC-06 mới là test case dành riêng cho
  nó, ở đây chỉ ghi nhận rằng một phiên cho **hai** event HTTP ở hai chiều khác nhau.
- `..` trong URI **không** làm event thành malformed: tầng parser chỉ bóc tách trung thực, việc kết
  luận "đây là path traversal" thuộc về luật phát hiện ở bài sau (ADR-3: pipeline không chứa chính
  sách). Đây là lý do `uri` phải giữ nguyên văn.
