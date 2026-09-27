# TC-06 — HTTP response

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-7.3 (status code là số nguyên + header của response), REQ-7.1 (version, reason) |
| Task | T7.4 · Phase 7 |
| Ngày ghi | 2026-09-27 |
| Traffic | **hai** phiên `curl`: `/` → `200 OK`, `/khong-ton-tai` → `404 Not Found` |
| Kết quả | 20 packet, `processed=20 unknown=0 malformed=0` |
| `md5sum input.pcap` | `d8fb6478c12e3b8b99ab2f7121b014ae` |

## 1. Kịch bản

Một response thành công **không đủ** để kiểm REQ-7.3, nên file này chứa hai phiên:

- `curl http://10.20.0.10/` → `HTTP/1.1 200 OK`, 8 header, body 11 byte;
- `curl http://10.20.0.10/khong-ton-tai` → `HTTP/1.1 404 Not Found`, 5 header, body 146 byte.

Phiên thứ hai thêm đúng hai thứ mà phiên đầu không có:

1. **Reason phrase có dấu cách** (`Not Found`). Status line được tách bằng `split(" ", 2)` — giới hạn
   2 lần — nên mọi thứ sau con số là reason. Nếu tách không giới hạn (như cách làm với **request**
   line) thì `Not Found` biến thành hai phần và parser sẽ báo lỗi cú pháp trên một response hoàn toàn
   hợp lệ.
2. **Một mã không phải 2xx**, để cột `status_code` chứng minh được lý do nó là `int` (§5).

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-06_http-response
docker compose exec -T attacker tcpdump -i eth0 -U -c 20 -w - \
    'tcp and host 10.20.0.10 and port 80' > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker curl -s -o /dev/null http://10.20.0.10/
sleep 1
docker compose exec -T attacker curl -s -o /dev/null http://10.20.0.10/khong-ton-tai
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

`-c 20` = 2 phiên × 10 packet, tcpdump tự thoát (lý do ở `TC-02/README.md` §2). `sleep 1` giữa hai
`curl` để thứ tự hai phiên trong file luôn như nhau.

## 3. Kết quả mong đợi

Điều kiện dừng của T7.4: có dòng `"kind":"response"` với `"status_code":200` (**số nguyên, không có
dấu nháy**) và `headers` không rỗng.

## 4. Kết quả thực tế

```sh
$ grep -c '"kind":"response"' TEST/TC-06_http-response/output.jsonl
2
$ grep -o '"status_code":[0-9][0-9]*' TEST/TC-06_http-response/output.jsonl
"status_code":200
"status_code":404
$ grep -o '"reason":"[^"]*"' TEST/TC-06_http-response/output.jsonl
"reason":"OK"
"reason":"Not Found"
$ cat TEST/TC-06_http-response/run.log
processed=20 unknown=0 malformed=0
```

`200` và `404` xuất hiện **không có dấu nháy** → chúng là số nguyên JSON, không phải chuỗi. Số header:
8 (response 200) và 5 (response 404) → khác rỗng. **Đạt.**

Response 200 (packet 6):

```json
{"kind": "response", "method": null, "uri": null, "version": "HTTP/1.1",
 "status_code": 200, "reason": "OK",
 "headers": [["Server", "nginx"], ["Date", "Sun, 27 Sep 2026 12:49:28 GMT"],
             ["Content-Type", "text/html"], ["Content-Length", "11"],
             ["Last-Modified", "Sun, 27 Sep 2026 07:06:40 GMT"],
             ["Connection", "keep-alive"], ["ETag", "\"6ab8c080-b\""],
             ["Accept-Ranges", "bytes"]],
 "body_len": 11, "body_b64": "dmljdGltIGxhYgo=", "incomplete": false}
```

Response 404 (packet 16): `status_code: 404`, `reason: "Not Found"`, `body_len: 146`, body là trang
lỗi HTML của nginx.

## 5. Vì sao `status_code` phải là `int` chứ không phải `str`

Luật phát hiện ở bài sau so sánh theo **khoảng**: "mọi response 4xx tới cùng một URI từ cùng một IP"
là hình dạng của brute force hoặc dò thư mục. So sánh chuỗi cho kết quả sai ngay ở ca đơn giản nhất:

```python
>>> "99" > "404"      # so từng ký tự: '9' > '4'
True
>>> 99 > 404
False
```

Nên `_parse_status_line()` kiểm **đúng 3 ký tự và cả 3 phải thuộc `"0123456789"`** rồi mới `int()`.
Không dùng `str.isdigit()`: hàm đó trả `True` cho chữ số của hệ chữ khác (vd `"٢٠٠"`) và cho cả `"²"`,
nên `int()` sau đó có thể ra một con số **không ai gửi**.

## 6. Cặp `method`/`uri` so với cặp `status_code`/`reason`

| | request (packet 4, 14) | response (packet 6, 16) |
|---|---|---|
| `kind` | `"request"` | `"response"` |
| `method`, `uri` | `"GET"`, `"/"` | `null`, `null` |
| `status_code`, `reason` | `null`, `null` | `200`/`404`, `"OK"`/`"Not Found"` |

Cả bốn khoá **luôn có mặt** ở mọi event, chỉ khác giá trị (I-2). Nhờ vậy `event["app"]["status_code"]`
đọc được mà không cần `.get()`, và một dòng `grep '"status_code":4'` tìm được mọi response 4xx mà
không vướng dòng request.

`kind` suy từ chữ ký `HTTP/1.` ở **byte đầu** payload, trước khi chia dòng — nên kể cả khi trong
buffer chưa trọn một dòng nào thì event vẫn nói được đây là request hay response.

## 7. Nhận xét

- Header `ETag` có giá trị `"6ab8c080-b"` **kèm dấu nháy kép** — đây là một phần của giá trị theo
  RFC 9110, không phải cú pháp JSON. Trong `output.jsonl` nó xuất hiện dưới dạng `"\"6ab8c080-b\""`:
  bằng chứng rằng giá trị header được giữ **nguyên văn** và `json.dumps` escape hộ, không phải parser
  tự cắt bỏ (I-3).
- Hai phiên có port nguồn khác nhau (`33366` và `33378`). Event không có khái niệm "phiên" —
  ghép packet thành flow là việc của module bài sau (thiết kế đã dành chỗ: sink có trạng thái, D9).
  Ở bài 1, thứ nối hai packet của cùng một phiên lại với nhau chỉ là 5-tuple trong từng event.
- Cả 20 packet `status="ok"`, `malformed=0`: parser HTTP nghiêm ngặt (chỉ nhận CRLF, chỉ nhận ASCII,
  không cho khoảng trắng quanh dấu `:`) **không** báo sai trên response thật của nginx — cùng một kết
  luận với V6.1, lần này trên cả ca 404.
