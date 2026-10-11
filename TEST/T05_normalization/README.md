# T05 — Normalization

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-27.1–27.4 (chuẩn hoá tên header, giao thức, IP, host), REQ-27.8 (giá trị gốc vẫn còn), Phụ lục K T05 |
| Task | T5.4 · Phase 5 (bài 2) |
| Ngày ghi | 2026-10-11 |
| Traffic | một `curl` với ba header **kiểu chữ lẫn lộn** (`HoSt`, `X-CuStOm-Tag`, `ConTent-TyPe`), host viết `VICTIM.lab`, path `/A/b` |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0`, 1 flow, exit 0 |
| `md5sum input.pcap` | `a2f54f3ad4059dd62d8446346bcb7d59` |

## 1. Kịch bản

Kẻ tấn công chọn kiểu chữ, không phải chuẩn nào bắt. HTTP nói tên header **không phân biệt** hoa
thường, nên `HoSt:` và `host:` là **cùng** một header — nhưng một luật viết `if "Content-Type" in
headers` thì trượt hết `ConTent-TyPe`. Vì vậy Preprocessor phải tạo một **biểu diễn chuẩn** để tầng
phát hiện so chuỗi trên đó, thay vì bắt mỗi luật tự xử lý mọi biến thể kiểu chữ.

Request này gửi cùng lúc bốn thứ cần chuẩn hoá: tên header lẫn lộn, tên miền hoa (`VICTIM.lab`),
`app_proto` do detector sinh ra, và IP nguồn/đích.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 80" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  curl -s -o /dev/null -H "HoSt: VICTIM.lab" -H "X-CuStOm-Tag: AbC" \
       -H "ConTent-TyPe: TEXT/Plain" "http://10.20.0.10/A/b"
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T05_normalization/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T05_normalization
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

## 3. Kết quả mong đợi

Điều kiện dừng T5.4: `preprocess.http_header_names` toàn chữ thường và **cùng số phần tử** với
`app.headers`; `preprocess.src_ip`/`dst_ip` dạng chuẩn; `preprocess.app_proto` in hoa; giá trị gốc
vẫn còn (REQ-27.8).

## 4. Kết quả thực tế

| Khoá | Giá trị gốc (bài 1) | Sau Preprocessor |
|---|---|---|
| header | `[["Host","VICTIM.lab"], ["User-Agent","curl/8.14.1"], ["Accept","*/*"], ["X-CuStOm-Tag","AbC"], ["ConTent-TyPe","TEXT/Plain"]]` | `http_header_names = ["host","user-agent","accept","x-custom-tag","content-type"]` |
| host | header `Host: VICTIM.lab` | `http_host = "victim.lab"` |
| giao thức | `app_proto = "HTTP"` | `app_proto = "HTTP"`, `transport_proto = "TCP"` |
| IP | `10.10.0.10` → `10.20.0.10` | `src_ip = "10.10.0.10"`, `dst_ip = "10.20.0.10"` |
| path | `app.uri = "/A/b"` | `path = "/A/b"`, `query_string = null` |

5 header gốc → **5** phần tử trong `http_header_names` (không gộp, không bỏ). `status = valid`,
`reasons = []`, `processed=10 unknown=0 malformed=0`, exit 0.

## 5. Nhận xét

- **Giá trị gốc không bị ghi đè (REQ-27.8).** `app.headers` vẫn giữ `ConTent-TyPe`/`VICTIM.lab` đúng
  từng ký tự như trên dây; bản chuẩn hoá nằm ở **khoá riêng** của `preprocess`. Lý do: nếu chuẩn hoá
  tại chỗ thì khi điều tra không còn biết kẻ tấn công gõ gì, và mọi so sánh với PCAP đều lệch. Đây
  cũng là điều kiện để chống **evasion do chuẩn hoá lệch**: ta có cả hai dạng nên so được.
- **Chuẩn hoá chỉ áp lên thứ chuẩn cho phép.** Tên header, tên miền, tên giao thức: không phân biệt
  hoa thường → đưa về một dạng. Nhưng **path thì có** phân biệt (`/A/b` ≠ `/a/b` trên hầu hết web
  server) nên `path` giữ nguyên kiểu chữ. Hạ chữ path là tự tạo ra lỗ hổng: luật chặn `/admin` sẽ
  khớp cả `/ADMIN` trong khi server thật trả 404, và ngược lại luật so sánh bằng sẽ trượt.
- **`http_header_names` là *danh sách tên*, không phải dict.** Giữ list để **không mất** header trùng
  tên (hai `Content-Length` là hình dạng của request smuggling — đã kiểm ở TC-04 bài 1) và giữ đúng
  thứ tự xuất hiện; dict sẽ gộp mất bằng chứng.
- **Số phần tử phải khớp `app.headers`** — đó là cách đo "chuẩn hoá không làm mất dữ liệu", nên nó
  nằm trong điều kiện dừng chứ không chỉ là nhận xét.
