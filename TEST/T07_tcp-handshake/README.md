# T07 — TCP handshake

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-30.1 (gom hai chiều vào một flow), REQ-31.1–31.3 (`HANDSHAKE` → `ESTABLISHED`), REQ-31.8 + V6.2 (bắt giữa phiên), Phụ lục K T07 |
| Task | T6.2 · Phase 6 (bài 2) |
| Ngày ghi | 2026-10-13 |
| Traffic | một `curl` GET từ `attacker` tới `victim:80`, chạy hết phiên (SYN … FIN) |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0`, 1 flow, exit 0 |
| `md5sum input.pcap` | `fecc21428e2ef89f15fa73334cd97049` |

## 1. Kịch bản

Một phiên HTTP đủ vòng đời, bắt từ packet SYN đầu tiên. Ca này không kiểm nội dung HTTP mà kiểm
**việc đọc ra kết nối** từ dãy packet rời:

1. Ba packet đầu là bắt tay ba bước. Tracker phải phân biệt được "đang mở" với "đã mở": một SYN
   không được trả lời là hình dạng của quét cổng, còn SYN → SYN/ACK → ACK là một kết nối thật.
   Nếu gộp cả hai vào một trạng thái thì luật phát hiện quét cổng ở bài sau không còn gì để dựa vào.
2. Chỉ **SYN thuần** mới mở `HANDSHAKE` (REQ-31.1). Packet đầu là SYN+ACK hoặc ACK nghĩa là phiên đã
   chạy trước khi ta bắt được — đó là `midstream`, không phải lỗi (REQ-31.8, kiểm ở §5).
3. Cả hai chiều phải rơi vào **một** `flow_id`: khoá flow sắp thứ tự hai endpoint rồi mới tra bảng,
   nên A→B và B→A cho cùng một ô (REQ-30.1).

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

# Bắt gói trong container attacker rồi mới mang ra host (-Z root: xem README của T01 §5)
docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 80" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  curl -s -o /dev/null "http://10.20.0.10/"
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T07_tcp-handshake/input.pcap

# Chạy pipeline (HOST_UID/HOST_GID để output thuộc user host)
export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T07_tcp-handshake
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

Lấy `$?` **trước** `grep` và lọc dòng `^ *Container ` — hai điểm này giải thích ở README của T01 §2;
không làm vậy thì `run.log` khác nhau từng lần chạy và bằng chứng không còn tái lập (V6.1).

## 3. Kết quả mong đợi

Điều kiện dừng T6.2: exit 0; chạy lại khớp **từng byte** (`git status --short` rỗng); `flows.jsonl`
có **một** dòng; `flow.state` trên ba event đầu của `output.jsonl` là `HANDSHAKE` → `HANDSHAKE` →
`ESTABLISHED`.

Nhánh hỏng hay gặp, phân biệt được ngay trên màn hình:

- `flows.jsonl` có **hai** dòng → khoá flow không sắp thứ tự endpoint, chiều ngược thành flow riêng.
- event 3 vẫn `HANDSHAKE` → điều kiện `final_ack` không thấy SYN+ACK chiều ngược (`seen_synack`).
- event 2 đã `ESTABLISHED` → đang xét `seen_synack` **sau** khi cập nhật, tức là SYN+ACK tự đóng vai
  ACK cuối; khi đó một SYN+ACK lẻ của quét cổng cũng bị tính là kết nối thành công.

## 4. Kết quả thực tế

```
$ cat run.log
config={"max_active_flows":10000,...,"tcp.established":3600,"tcp.new":60,...}
processed=10 unknown=0 malformed=0
flows_created=1 flows_closed=1 close.end_of_run=1 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

`flow.state` đọc từ `output.jsonl`, một dòng một packet:

| # | `direction` | `tcp.flags` | `flow.state` sau packet |
|---|---|---|---|
| 1 | forward | `SYN` | `HANDSHAKE` |
| 2 | backward | `SYN`, `ACK` | `HANDSHAKE` |
| 3 | forward | `ACK` | `ESTABLISHED` |
| 4 | forward | `PSH`, `ACK` (GET / HTTP/1.1) | `ESTABLISHED` |
| 5–7 | backward/forward | `ACK`, `PSH+ACK`, `ACK` | `ESTABLISHED` |
| 8 | forward | `FIN`, `ACK` | `CLOSING` |
| 9 | backward | `FIN`, `ACK` | `CLOSING` |
| 10 | forward | `ACK` | `CLOSED` |

Cả 10 event có `flow.flow_id` = `1` và `flow.reasons` = `[]`. Flow record (`flows.jsonl`, một dòng):
`state` = `CLOSED`, `midstream` = `false`, `packet_count` = 10 (forward 6 / backward 4),
`syn_count` = 2, `ack_count` = 9, `fin_count` = 2, `rst_count` = 0,
`application_protocol` = `HTTP`, `close_reason` = `end_of_run`.

## 5. Nhận xét

- **Chuỗi chuyển trạng thái đọc ở `output.jsonl`, không ở `flows.jsonl`.** Flow record là bản *chốt
  sổ*: nó chỉ có một dòng cho cả phiên, và `state` trong đó là trạng thái **cuối** (`CLOSED`). Thứ
  cần kiểm ở ca này là *đường đi* `HANDSHAKE → ESTABLISHED`, mà đường đi chỉ tồn tại theo từng
  packet. Vì vậy `state` được ghi lên **event**, giá trị là trạng thái **sau khi** đã tính packet đó
  (REQ-35.2). Nếu chỉ có trạng thái ở flow record thì không ai phân biệt được một flow `CLOSED` đi
  qua bắt tay đầy đủ với một flow `CLOSED` bắt được giữa phiên.
- **`ack_count` = 9 chứ không phải 7.** Bộ đếm đếm **cờ**, không đếm vai trò: SYN+ACK cộng vào cả
  `syn_count` và `ack_count`, FIN+ACK cộng vào cả `fin_count` và `ack_count` (REQ-34.5). Đếm theo
  vai trò thì phải đoán ý nghĩa của packet, mà đoán sai thì con số không còn kiểm chứng được bằng
  `tshark`.
- **`byte_count` hai chiều không bằng nhau** (forward 478 / backward 511) dù số packet forward nhiều
  hơn: chiều backward chở response 239 byte. Đây là lý do thống kê phải tách theo chiều — tỉ lệ
  gửi/nhận là dấu hiệu của bài sau, tổng gộp lại thì mất.
- **Bắt giữa phiên (V6.2, REQ-31.8).** Cắt bỏ đúng packet SYN đầu rồi chạy lại:

  ```sh
  tcpdump -r TEST/T07_tcp-handshake/input.pcap -w tmp/midstream.pcap \
      'not (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)'
  docker compose run --rm idps-offline python main.py --pcap tmp/midstream.pcap \
      -o /tmp/m.jsonl --flow-output /tmp/mf.jsonl
  ```

  Kết quả: `processed=9`, exit `0`, **1** flow, `midstream` = `true`, `state` trên event đầu là
  `ESTABLISHED`, `0` lỗi của cả bốn tầng. `endpoint_a` lúc này là `10.20.0.10:80` chứ không phải
  attacker, vì endpoint A là **nguồn của packet đầu tiên thấy được** — packet đầu còn lại là SYN+ACK
  của victim. Hai chiều vì vậy đảo tên so với bản đầy đủ, nhưng vẫn là một flow duy nhất. PCAP này
  là tạm, không commit.
