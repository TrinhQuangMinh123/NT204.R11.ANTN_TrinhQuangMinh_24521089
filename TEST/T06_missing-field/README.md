# T06 — Thiếu field không bắt buộc

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-26.3 (thiếu field không bắt buộc → `partial`, vẫn xử lý tiếp và vẫn được gán flow), REQ-28.1 (`null`/`[]` nhất quán), REQ-38.6, Phụ lục K T06 |
| Task | T5.8 · Phase 5 (bài 2) |
| Ngày ghi | 2026-10-11 |
| Traffic | **dùng lại** `TEST/TC-12_malformed-packet/input.pcap` của bài 1 (10 bản ghi dựng bằng `tests/tools/make_bad_pcaps.py`, ADR-11) — ca chính là packet #5 `tcp-data-offset-15` |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=10`, 3 flow, exit 0 |
| `md5sum input.pcap` | `0ec8ea921fd1dbbe544da1e9fff55e72` (khớp bản của TC-12) |

## 1. Kịch bản

Packet #5 của PCAP này khai `data_offset = 15` (header TCP 60 byte) trên một segment chỉ có 20 byte.
Parser TCP của bài 1 dừng đúng chỗ đó, nhưng **phần đã đọc được vẫn giữ**: `src_port = 40470`,
`dst_port = 80`, cờ TCP. Kết quả là một event **có 5-tuple đầy đủ nhưng không có dữ liệu tầng ứng
dụng** — đúng hình dạng "thiếu field không bắt buộc" mà REQ-26.3 mô tả, và là loại event mà một IDS
gặp liên tục ngoài thực tế (packet bị cắt, header hỏng, segment giữa luồng).

Câu hỏi test đặt ra: Preprocessor có **ném** event này đi không, và FlowTracker có **bỏ** nó khỏi
thống kê flow không? Cả hai đều không được, vì 5-tuple vẫn là bằng chứng dùng được.

Vì sao dùng lại PCAP của bài 1 thay vì thêm một chế độ nạp bản ghi (Q17): các packet hỏng kiểu này
**không hệ điều hành nào tạo ra** (kernel tự tính `data_offset`), nên dữ liệu phải do script dựng —
mà script đó đã có ở bài 1 và đã được commit cùng PCAP. Thêm một đường nạp event dựng tay vào
`main.py` chỉ để test thì lại thêm bề mặt mã không dùng khi chạy thật.

## 2. Lệnh tái hiện

```sh
cp TEST/TC-12_malformed-packet/input.pcap TEST/T06_missing-field/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T06_missing-field
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

(PCAP gốc sinh lại được bằng `python tests/tools/make_bad_pcaps.py`, sha256 in ra để đối chiếu.)

## 3. Kết quả mong đợi

Điều kiện dừng T5.8: exit 0; ≥ 1 dòng `preprocess.status` = `partial` với `reasons` ≥ 1; khoá tầng
ứng dụng là `null`/`[]` (**không** phải `""`/`0`); event **vẫn** được gán flow.

## 4. Kết quả thực tế

Event của packet #5 (`tcp-data-offset-15`):

| Khoá | Giá trị |
|---|---|
| `src_port` / `dst_port` | `40470` / `80` |
| `app` / `app_proto` | `null` / `null` |
| `preprocess.status` / `reasons` | `partial` / `["upstream_status=malformed"]` |
| `preprocess.http_host` / `path` / `query_string` | `null` / `null` / `null` |
| `preprocess.http_header_names` / `dns_names` | `[]` / `[]` |
| `decode.status` | `not_applicable` |
| `flow.flow_id` / `direction` / `state` | `1` / `forward` / `ESTABLISHED` |

Toàn tệp: 10 event / 10 packet · `malformed=10` · 3 flow, cả 3 đóng với `end_of_run` ·
`decode_errors=0 preprocess_errors=0 flow_errors=0` · exit 0. Lỗi chỉ nằm ở các tầng của **bài 1**
(`ipv4` 4, `tcp` 2, `dns` 2, `udp` 1, `http` 1, `capture` 1) — đúng NFR-10: bốn tầng của bài 2 không
sinh thêm lỗi nào từ dữ liệu hỏng.

## 5. Nhận xét

- **`null` và `[]`, không bao giờ `""` hay `0`.** Phân biệt "không có dữ liệu" với "có dữ liệu rỗng"
  là việc của schema: `http_header_names = []` nghĩa là *không có header nào*, còn `""` sẽ bị một luật
  `if host == ""` hiểu thành *host rỗng*. Tập khoá thì **giống nhau ở mọi event** (REQ-25.3/28.1), nên
  phía tiêu thụ không phải kiểm tra sự tồn tại của khoá trước khi đọc.
- **`partial` chứ không `invalid`.** Event này không sai — nó **thiếu**. `invalid` dành cho dữ liệu
  mâu thuẫn với chính nó (port ngoài khoảng, timestamp sai dạng); phân biệt hai mức này là cách để
  tầng phát hiện quyết định "soi tiếp" hay "bỏ qua".
- **`reasons = ["upstream_status=malformed"]`** cho biết lý do thiếu dữ liệu đến từ **tầng trước**
  (bài 1 đã đánh dấu packet là malformed), không phải do Preprocessor tự thấy field nào sai. Giữ
  nguồn gốc của lý do giúp đọc log biết nên sửa parser hay sửa luật chuẩn hoá.
- **Vẫn được gán flow (REQ-26.3) — đây là điểm then chốt.** Packet này được tính vào flow `1` cùng với
  hai packet HTTP hợp lệ khác của cùng 5-tuple, nên `packet_count`/`byte_count` của flow **không** bị
  hụt. Nếu bỏ event hỏng khỏi flow thì kẻ tấn công chỉ cần làm hỏng vài packet là làm sai mọi đặc
  trưng theo flow (tỉ lệ gửi/nhận, số packet) mà không để lại dấu vết nào.
- **`state = ESTABLISHED` dù packet đầu không phải SYN** (`midstream`): PCAP này chỉ có từng packet
  rời rạc, không có handshake. Máy trạng thái coi đó là flow bắt giữa luồng thay vì từ chối theo dõi —
  đúng việc một IDS phải làm khi được bật lên giữa lúc mạng đang chạy.
