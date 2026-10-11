# T02 — HTML entity decode

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-22.1 (giải entity), REQ-22.5 (thiếu dấu `;` → `partial`), REQ-22.6 (luật khớp dài nhất của HTML5), ADR-27, Phụ lục K T02 |
| Task | T5.3 · Phase 5 (bài 2) |
| Ngày ghi | 2026-10-11 |
| Traffic | ba `curl`: `?html=&lt;script&gt;` · `?html=&ltscript&gt` · `?html=&notit;` |
| Kết quả | 30 packet, `processed=30 unknown=0 malformed=0`, 3 flow, exit 0 |
| `md5sum input.pcap` | `63bb2707e44e76544555971ed4d3f59d` |

## 1. Kịch bản

Ba request là ba **ranh giới** khác nhau của việc giải entity, hai ca sau chốt thêm 2026-10-06 ở ADR-27:

1. `&lt;script&gt;` — ca đúng chuẩn, có dấu `;`. Đây là cách chèn thẻ `<script>` qua một tham số mà
   luật soi chữ `<script>` trên dây sẽ trượt.
2. `&ltscript&gt` — **thiếu dấu `;`**. Trình duyệt vẫn hiểu là `<script>` (HTML5 cho phép một tập
   entity không cần `;`), nên IDS **phải** giải ra `<script>` chứ không được bỏ qua. Nhưng nó cũng là
   dấu hiệu bất thường, nên kết quả là `partial` kèm vị trí — đó là thông tin cho tầng phát hiện, chứ
   `partial` ở đây **không** có nghĩa "giải mã thất bại" (ADR-27).
3. `&notit;` — luật **khớp dài nhất** của HTML5: `&not` là entity hợp lệ (`¬`) nhưng `&notit;` thì
   không, nên kết quả đúng là `¬it;`, **không** phải giữ nguyên cả chuỗi và cũng không phải báo lỗi.
   Ai tự viết bộ giải entity bằng cách "tìm `&`…`;` rồi tra bảng" sẽ ra kết quả khác ở đúng ca này.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 80" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  curl -s -o /dev/null "http://10.20.0.10/x?html=&lt;script&gt;"
  curl -s -o /dev/null "http://10.20.0.10/x?html=&ltscript&gt"
  curl -s -o /dev/null "http://10.20.0.10/x?html=&notit;"
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T02_html-entity/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T02_html-entity
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

## 3. Kết quả mong đợi

Điều kiện dừng T5.3: bốn tệp bằng chứng, chạy lại khớp từng byte; output chứa `<script>` đã giải
entity; hai ca mới ra `<script>` và `¬it;`, cả hai kèm `decode.status` = `partial` + reason.

## 4. Kết quả thực tế

| # | `app.uri` (gốc) | `decode.uri.value` | `decode.uri.status` | `reasons` |
|---|---|---|---|---|
| 1 | `/x?html=&lt;script&gt;` | `/x?html=<script>` | `ok` | `[]` |
| 2 | `/x?html=&ltscript&gt` | `/x?html=<script>` | `partial` | `entity_without_semicolon_at=8`, `entity_without_semicolon_at=17` |
| 3 | `/x?html=&notit;` | `/x?html=¬it;` | `partial` | `unknown_entity_at=8` |

`processed=30 unknown=0 malformed=0`, `decode_errors=0 preprocess_errors=0 flow_errors=0`, exit 0.

## 5. Vì sao `partial` là kết quả ĐÚNG, không phải lỗi (ADR-27)

`partial` trong bài này nghĩa là *"đã tạo ra được một giá trị dùng được, nhưng dữ liệu vào có chỗ
không đúng chuẩn"* — khác hẳn `invalid` (giải mã thất bại) và `not_applicable` (phép giải mã không áp
dụng). Ở ca 2 và 3, giá trị trả về là đúng thứ trình duyệt sẽ hiểu, nên tầng phát hiện **vẫn phải
dùng được nó**; đồng thời `reasons` giữ bằng chứng "chuỗi này không đúng chuẩn và đây là vị trí" —
dấu hiệu cố ý né luật. Gộp hai ca này thành `ok` thì mất tín hiệu; gộp thành `invalid` thì mất luôn
giá trị đã giải mã và kẻ tấn công chỉ cần bỏ dấu `;` là đi qua được.

Phần giải mã dùng `html.unescape` của thư viện chuẩn (đã có luật khớp dài nhất của HTML5 chuẩn xác);
phần **tự viết** là bộ dò trạng thái: quét từng tham chiếu entity trên chuỗi nguồn, so với bảng
`html.entities.html5` để biết nó thiếu `;` hay không có trong bảng, rồi quyết định `status`/`reasons`
(ADR-20 phương án B — thư viện *biến đổi* byte, mình *phân loại* kết quả).

## 6. Nhận xét

- **Bằng chứng entity nằm ở `decode.uri`, không ở `decode.query`.** `decode.query` áp F2 (form decode)
  nên nó tách theo `&` **trước**: `&lt;script&gt;` biến thành ba cặp (`html=`, `lt;script=`, `gt;=`).
  Đó không phải bug — `&` đúng là dấu ngăn cặp của `application/x-www-form-urlencoded`, và cũng chính
  là lý do một payload chứa entity phải được soi ở **nhiều** biểu diễn: luật soi `decode.query` sẽ
  trượt, luật soi `decode.uri` thì không. Trong event có cả hai nên tầng phát hiện tự chọn.
- **`preprocess.status` = `valid` dù `decode.status` = `partial`.** Hai stage đo hai việc khác nhau:
  decoder nói "chuỗi vào không đúng chuẩn", preprocessor nói "event có đủ field hợp lệ để xử lý".
  Trộn chúng lại thì không phân biệt được "dữ liệu lạ" với "event thiếu field".
