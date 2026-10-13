# T09 — TCP close và reset

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-31.4 (`CLOSING`), REQ-31.5 (`CLOSED`), REQ-31.6 (`RESET`), REQ-31.9 (packet sau khi đóng), Phụ lục K T09 |
| Task | T6.4 · Phase 6 (bài 2) |
| Ngày ghi | 2026-10-13 |
| Traffic | hai phiên trong **một** PCAP: `curl` GET `victim:80` (đóng bằng FIN hai chiều) và `curl` tới `victim:8080` — không ai nghe port đó nên kernel của victim trả RST |
| Kết quả | 12 packet, `processed=12 unknown=0 malformed=0`, 2 flow, exit 0 |
| `md5sum input.pcap` | `575a699fc0d6bb9970a717d546da7fe9` |

## 1. Kịch bản

Hai đường kết thúc của TCP, hai nhánh khác nhau của bảng chuyển trạng thái, nên phải có bằng chứng
cho **cả hai**:

1. **Đóng thương lượng** — mỗi bên gửi FIN rồi ACK lại FIN của bên kia: `ESTABLISHED` → `CLOSING` →
   `CLOSED`. Đây là đường bình thường của một phiên HTTP xong việc.
2. **Đóng bằng RST** — một bên bỏ kết nối ngay: `RESET`. Lấy RST thật từ lab bằng cách gọi vào
   `10.20.0.10:8080` (victim chỉ nghe 80, 8081 và 25): không có process nào nhận SYN nên **kernel**
   của victim trả RST+ACK. Đây cũng đúng là hình dạng của một lần quét cổng gặp cổng đóng, nên packet
   này có giá trị cho luật phát hiện bài sau.

Hai phiên nằm trong một PCAP (`tcpdump "tcp"`, không lọc theo port) để cùng lúc chứng minh thêm:
tracker không trộn hai phiên khác port vào một flow.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  curl -s -o /dev/null "http://10.20.0.10/"
  curl -s -o /dev/null --max-time 3 "http://10.20.0.10:8080/"
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T09_tcp-close/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T09_tcp-close
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

`--max-time 3` cho lệnh thứ hai: nếu môi trường nào đó **nuốt** gói RST thay vì chuyển nó về thì
`curl` sẽ chờ hết timeout kết nối rồi thoát, PCAP chỉ có SYN truyền lại — hỏng ca test nhưng không
treo script.

## 3. Định nghĩa đã dùng cho "một ACK sau FIN cuối"

Đề bài (REQ-31.5) không nói rõ ACK nào. Thiết kế §6 chốt: **sau khi cả hai chiều đã gửi FIN, packet
đầu tiên tiếp theo có cờ ACK — chiều nào cũng được — chuyển `CLOSING` → `CLOSED`.**

Không theo `seq`/`ack` để xác minh ACK đó đúng là ACK của FIN cuối, vì theo được số thứ tự thì phải
ghép cả luồng TCP, mà việc đó ngoài phạm vi bài (requirements §3.2). Đánh đổi: một ACK của dữ liệu
truyền lại, đến sau khi hai FIN đã đi qua, cũng bị tính là ACK đóng kết nối. Chấp nhận được vì sau
thời điểm đó phiên coi như đã xong; và nhờ định nghĩa này, điều kiện kiểm được bằng **bốn** packet,
không cần dựng trạng thái luồng.

## 4. Kết quả mong đợi

Điều kiện dừng T6.4: exit 0; chạy lại khớp **từng byte**; có bằng chứng cho **cả hai** đường — một
flow đạt `CLOSED`, một flow đạt `RESET`.

Nhánh hỏng hay gặp:

- flow 1 dừng ở `CLOSING` → đang đòi ACK **đúng** của FIN cuối (so `seq`), hoặc chỉ nhận ACK từ một
  chiều cố định.
- flow 1 thành `CLOSED` ngay ở packet 8 (FIN đầu) → điều kiện chỉ xét "có FIN" mà không xét **hai**
  chiều đã FIN.
- flow 2 ở `HANDSHAKE` → RST không được xét, hoặc bị xét **sau** các dòng khác trong bảng chuyển
  trạng thái.
- 12 event trong **một** flow → khoá flow bỏ port, chỉ còn cặp IP.

## 5. Kết quả thực tế

```
$ cat run.log
processed=12 unknown=0 malformed=0
flows_created=2 flows_closed=2 close.end_of_run=2 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

| # | `flow_id` | `direction` | `tcp.flags` | `flow.state` sau packet |
|---|---|---|---|---|
| 1 | 1 | forward | `SYN` | `HANDSHAKE` |
| 2 | 1 | backward | `SYN`, `ACK` | `HANDSHAKE` |
| 3 | 1 | forward | `ACK` | `ESTABLISHED` |
| 4–7 | 1 | forward/backward | `PSH+ACK`, `ACK`, `PSH+ACK`, `ACK` | `ESTABLISHED` |
| 8 | 1 | forward | `FIN`, `ACK` | `CLOSING` |
| 9 | 1 | backward | `FIN`, `ACK` | `CLOSING` |
| 10 | 1 | forward | `ACK` | `CLOSED` |
| 11 | 2 | forward | `SYN` | `HANDSHAKE` |
| 12 | 2 | backward | `RST`, `ACK` | `RESET` |

Hai flow record:

```
flow_id=1  10.10.0.10:53194 ↔ 10.20.0.10:80    app=HTTP
           packets=10 (6/4)  bytes=989  syn=2 ack=9 fin=2 rst=0
           state=CLOSED  midstream=false  close_reason=end_of_run  duration_usec=1191

flow_id=2  10.10.0.10:44090 ↔ 10.20.0.10:8080  app=null
           packets=2 (1/1)   bytes=128  syn=1 ack=1 fin=0 rst=1
           state=RESET   midstream=false  close_reason=end_of_run  duration_usec=60
```

## 6. Nhận xét

- **Packet 9 vẫn là `CLOSING`, không phải `CLOSED`.** Nó mang FIN+ACK, tức là có cờ ACK, nhưng điều
  kiện được tra trên trạng thái **trước** packet này: lúc đó mới có FIN của một chiều. Chiều thứ hai
  được ghi nhận **sau** khi tra bảng. Nếu đổi thứ tự hai việc đó, packet 9 tự đóng luôn kết nối và
  `CLOSED` mất nghĩa "đã ACK xong".
- **`RST` thắng mọi điều kiện khác** — nó là dòng **đầu** của bảng chuyển trạng thái, với trạng thái
  nguồn "bất kỳ". Packet 12 mang cả RST và ACK; nếu bảng xét ACK trước thì flow 2 sẽ thành
  `ESTABLISHED`. Thứ tự dòng trong bảng **chính là** luật ưu tiên, không phải chi tiết cài đặt.
- **`state` = `CLOSED` nhưng `close_reason` = `end_of_run`.** Hai thứ khác nhau: `state` là trạng
  thái của **kết nối TCP**, `close_reason` nói vì sao **flow record được ghi ra**. Flow đã `CLOSED`
  vẫn nằm trong bảng cho tới khi im lặng quá ngưỡng `tcp.closed` (120 s) hoặc hết lần chạy — giữ lại
  là có chủ ý: packet FIN/ACK truyền lại sau đó phải được cộng vào flow cũ chứ không mở flow mới
  (REQ-31.9), và với PCAP 12 packet này thì lý do đóng luôn là `end_of_run`.
- **Flow 2 có `application_protocol` = `null`.** Không packet nào của nó mang payload nên bài 1 không
  nhận ra giao thức ứng dụng; tên giao thức lấy từ packet **đầu tiên có** `app_proto` thật, và ở đây
  không có packet nào như vậy. Đoán "port 8080 → HTTP" là đúng thứ bài 1 cố tình không làm.
- **`ack_count` = 1 ở flow 2** vì RST+ACK được đếm cả cờ ACK — cùng một quy ước đếm cờ như T07/T13.
