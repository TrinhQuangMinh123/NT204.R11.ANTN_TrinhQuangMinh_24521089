# T01 — HTTP URL decode

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-21.1, 21.2 (percent-decode URI, giữ nguyên bản gốc), REQ-21.5/I-14 (giải **một lần**), Phụ lục K T01 |
| Task | T5.2 · Phase 5 (bài 2) |
| Ngày ghi | 2026-10-11 |
| Traffic | hai `curl` từ `attacker` tới `victim`: `?q=%27%20OR%201%3D1` và `?q=%2527` |
| Kết quả | 20 packet, `processed=20 unknown=0 malformed=0`, 2 flow, exit 0 |
| `md5sum input.pcap` | `56f90903cd3f5f3f342bb2deb27b5378` |

## 1. Kịch bản

Hai request, mỗi request kiểm một tính chất khác nhau — không phải để có hai dòng giống nhau:

1. `?q=%27%20OR%201%3D1` — payload SQL injection đã được mã hoá URL. Đây là hình dạng thật của một
   lần lách IDS: luật phát hiện soi chuỗi `' OR 1=1` sẽ **trượt** nếu chỉ đọc bytes trên dây, vì trên
   dây không có dấu `'` nào. Decoder phải đưa cả hai dạng vào event: bản đã giải mã để luật soi, bản
   gốc để biết **đúng** bytes kẻ tấn công đã gửi (REQ-21.2).
2. `?q=%2527` — percent-decode phải chạy **đúng một lần**: `%25` là dấu `%`, nên kết quả là `%27`
   chứ **không** phải `'`. Giải đệ quy tới khi hết là lỗi kinh điển: nó biến một chuỗi *không* chứa
   `'` thành chuỗi chứa `'` và sinh false positive, đồng thời cho kẻ tấn công một cách che payload
   khỏi chính luật của mình (bất biến I-14).

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

# Bắt gói trong container attacker rồi mới mang ra host (xem §5 về -Z root)
docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 80" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  curl -s -o /dev/null "http://10.20.0.10/search?q=%27%20OR%201%3D1"
  curl -s -o /dev/null "http://10.20.0.10/search?q=%2527"
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T01_http-url-decode/input.pcap

# Chạy pipeline (HOST_UID/HOST_GID để output thuộc user host)
export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T01_http-url-decode
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

Hai điểm trong lệnh chạy **không** được đổi: lấy `$?` **trước** `grep` (sau pipe đó là mã của `grep`),
và lọc `^ *Container ` vì `docker compose run` in ra stderr dòng
`Container ids_ips-idps-offline-run-<hash> Creating` với `<hash>` đổi mỗi lần chạy — giữ nó lại thì
`run.log` khác nhau từng lần và bằng chứng không còn tái lập (V5.2).

## 3. Kết quả mong đợi

Điều kiện dừng T5.2: exit 0; chạy lại khớp **từng byte** (`git status --short` rỗng); dòng request có
`decode.uri.value` chứa `' OR 1=1` **và** `app.uri` vẫn chứa `%27%20OR%201%3D1`.

## 4. Kết quả thực tế

```
$ cat run.log
config={"max_active_flows":10000,"max_decode_bytes":65536,...}
processed=20 unknown=0 malformed=0
flows_created=2 flows_closed=2 close.end_of_run=2 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

| Request | `app.uri` (gốc, bài 1) | `decode.uri.value` (bài 2) | `rule` | `status` |
|---|---|---|---|---|
| 1 | `/search?q=%27%20OR%201%3D1` | `/search?q=' OR 1=1` | `F1+F4` | `ok` |
| 2 | `/search?q=%2527` | `/search?q=%27` | `F1+F4` | `ok` |

`decode.query` tách thêm từng cặp: `[["q", "' OR 1=1"]]` và `[["q", "%27"]]` (`rule` = `F2+F4`).
20 event / 20 packet, 16 event không có payload ứng dụng → `app_proto` = `null` và **0** lỗi
(`decode_errors=0 preprocess_errors=0 flow_errors=0`).

## 5. Nhận xét

- **`rule` là `F1+F4` chứ không phải `F1`.** URI đi qua hai phép: percent-decode (F1) rồi HTML entity
  (F4). Ghi nối bằng `+` để khi vấn đáp đọc ra ngay thứ tự đã áp (REQ-25.4). Ở đây F4 không đổi gì vì
  URI không có entity, nhưng `rule` vẫn phải nói đúng việc đã làm.
- **Bản gốc còn nguyên ở `app.uri`, không bị ghi đè.** Đây là ràng buộc cố ý: nếu decoder sửa tại chỗ
  thì không ai so lại được với bytes trên dây nữa, và `payload_b64` của bài 1 cũng mất ý nghĩa đối
  chiếu (REQ-21.2, I-4).
- **`preprocess.query_string` giữ dạng chưa decode** (`q=%27%20OR%201%3D1`). Chuẩn hoá của
  Preprocessor là chuẩn hoá **biểu diễn** (chữ hoa/thường, dạng IP), không phải giải mã — hai việc đó
  ở hai stage khác nhau và không được trộn.
- **`-Z root` trong lệnh `tcpdump`.** Container `attacker` bị `cap_drop: [ALL]`, nên tiến trình root
  **không** có `CAP_KILL` để gửi tín hiệu cho tiến trình đã hạ quyền xuống user `tcpdump`; không có
  `-Z root` thì `kill -INT` trả `Operation not permitted` và tệp pcap không bao giờ được đóng đúng.
  Đây là đánh đổi có ý thức: tcpdump chạy root **trong một container đã bỏ 14/14 capability** và
  không có default route, đổi lấy việc script dừng được tcpdump một cách tất định.
