# T04 — Byte không hợp lệ UTF-8

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-24.2 (luật thay thế cố định + vị trí/giá trị byte lỗi đầu tiên), REQ-24.3 (chạy tiếp, exit 0), REQ-38.6, ADR-21, Phụ lục K T04 |
| Task | T5.7 · Phase 5 (bài 2) |
| Ngày ghi | 2026-10-11 |
| Traffic | `curl 'http://10.20.0.10/x?q=%FF%27%20OR%201%3D1'` |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0`, **0** lỗi mọi tầng, exit 0 |
| `md5sum input.pcap` | `dd05411ee604e49bb3c1b248657f6ac5` |

## 1. Kịch bản và vì sao KHÔNG dùng lại PCAP hỏng của bài 1

Kế hoạch ban đầu (và `design.md` §9) định dùng lại `TEST/TC-12_malformed-packet/input.pcap` — packet
HTTP có byte `0xFF` trong một dòng header. **Đo lại 2026-10-11 thì ca đó không chạm tới Decoder của
bài 2:** parser HTTP của bài 1 decode header bằng `ascii` **nghiêm ngặt**, nên nó loại cả dòng header
đó và ghi lỗi tầng `http`; dòng header hỏng không vào `app.headers`, và event vẫn có
`decode.status = "ok"`. Nói cách khác, byte `0xFF` bị chặn **trước** bài 2 một tầng.

Nên T04 dùng một PCAP bắt mới, với `%FF` trong URI. Ca này đúng thứ REQ-24.2 nói tới và sát thực tế
hơn: byte không hợp lệ UTF-8 **sinh ra bởi chính phép giải mã của ta**. Trên dây request chỉ là ASCII
(`GET /x?q=%FF%27...`) nên không parser nào ở bài 1 phản đối; chỉ sau khi percent-decode mới xuất hiện
byte `0xFF`. Đây là hình dạng của một lần lách IDS: payload đi qua được tầng kiểm tra byte thô, rồi
mới bung ra ở tầng giải mã.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 80" > /tmp/cap.pcap 2>/dev/null &
  TD=$!; sleep 2
  curl -s -o /dev/null "http://10.20.0.10/x?q=%FF%27%20OR%201%3D1"
  sleep 2; kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T04_invalid-bytes/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T04_invalid-bytes
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

## 3. Kết quả mong đợi

Điều kiện dừng T5.7: exit `0`; ≥ 1 dòng `decode.status` = `partial` với reason chứa
`utf8_invalid_byte_at=` và `value=0xFF`; số dòng event = số packet; số lỗi `layer` ∈
{`decoder`,`internal`} = `0`.

## 4. Kết quả thực tế

```
decode.uri   = {"value": "/x?q=�' OR 1=1", "rule": "F1+F4", "status": "partial",
                "reasons": ["utf8_invalid_byte_at=5 value=0xFF"]}
decode.query = {"value": [["q", "�' OR 1=1"]], "rule": "F2+F4", "status": "partial",
                "reasons": ["utf8_invalid_byte_at=2 value=0xFF"]}
tcp.payload_b64 = "R0VUIC94P3E9JUZGJTI3JTIwT1IlMjAxJTNEMSBI…"   (bytes gốc còn nguyên)
```

10 event / 10 packet · `processed=10 unknown=0 malformed=0` · `decode_errors=0 preprocess_errors=0
flow_errors=0` · **0** lỗi `internal` · exit 0.

## 5. Nhận xét

- **`partial`, không phải `invalid`.** Có một giá trị dùng được (byte lỗi → `U+FFFD`) **và** có bằng
  chứng về chỗ sai (`utf8_invalid_byte_at=5 value=0xFF`). Tầng phát hiện vẫn soi được `' OR 1=1` nằm
  ngay sau byte rác — nếu ta ném cả chuỗi đi thì payload SQLi đó biến mất khỏi event.
- **Vì sao `U+FFFD` chứ không `surrogateescape`.** `errors="surrogateescape"` giữ được byte gốc nhưng
  sinh lone surrogate, mà `json.dumps` sẽ ghi ra chuỗi **không phải** Unicode hợp lệ → phá định dạng
  output (NFR-12). Byte gốc không mất đi: nó vẫn ở `tcp.payload_b64` của bài 1 (I-4), nên luật thay
  thế cố định ở đây không làm mất bằng chứng.
- **Vị trí byte lỗi khác nhau giữa `uri` (5) và `query` (2)** vì hai phép giải mã làm việc trên hai
  chuỗi khác nhau: F1 trên toàn URI (`/x?q=…` → offset 5), F2 trên phần query đã tách cặp (`q=…` →
  offset 2). Cùng một byte, hai hệ toạ độ — `rule` cho biết đang đọc toạ độ của phép nào.
- **`decode.query` báo `partial` là nhờ một sửa riêng** (commit `Report invalid UTF-8 bytes in form
  decode`): `urllib.parse.parse_qsl` decode UTF-8 với `errors="replace"` một cách **im lặng**, nên
  trước đó cùng một query cho `partial` ở `decode.uri` nhưng `ok` ở `decode.query` — tức event tự nói
  rằng dữ liệu bẩn đã được giải mã sạch. Nay F2/F3 dò lại trên bytes nguồn, dùng **cùng** hàm
  `to_text` với F1 nên hai chỗ không thể lệch luật nữa.
- **Byte lỗi tới từ đâu, bài 1 hay bài 2.** Ở TC-12 (bài 1) `0xFF` nằm **trên dây** → parser từ chối,
  lỗi tầng `http`. Ở T04 `0xFF` **xuất hiện sau khi decode** → không lỗi tầng nào, chỉ là
  `decode.status = partial`. Hai loại thông tin khác nhau và đúng hai chỗ: `errors[]` nói "bytes không
  khớp cú pháp giao thức", `decode.status` nói "đã decode nhưng dữ liệu vào không đúng chuẩn".
