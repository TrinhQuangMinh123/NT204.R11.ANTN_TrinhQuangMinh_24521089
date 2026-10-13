# T13 — Thống kê flow, đối chiếu với `tshark`

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-34.2 (packet/byte hai chiều), REQ-34.3 (byte tải), REQ-34.4 (`duration`), REQ-34.5 (counter cờ TCP), NFR-19 (đối chiếu `tshark`), Phụ lục K T13 |
| Task | T7.3 · Phase 7 (bài 2) |
| Ngày ghi | 2026-10-13 |
| Traffic | một kết nối HTTP keep-alive chở **ba** cặp request/response, rồi FIN hai chiều |
| Kết quả | 14 packet, `processed=14`, 1 flow, exit 0 |
| `md5sum input.pcap` | `f2851110f02f9151740a59dd8104167d` |
| Công cụ đối chiếu | `tshark` (Wireshark) 3.6.2 trên host — ngoài container |

## 1. Kịch bản

Một `curl` gọi **ba** URL cùng host trong một lần chạy. `curl` dùng lại kết nối (HTTP keep-alive),
nên 14 packet này là **một** phiên TCP chở ba cặp request/response:

| packet | nội dung |
|---|---|
| 1–3 | bắt tay ba bước |
| 4–7 | `GET /` → `200 OK` (text/html) + hai ACK |
| 8–9 | `GET /index.html` → `200 OK` |
| 10–11 | `GET /submit` → `200 OK` |
| 12–14 | FIN hai chiều + ACK cuối |

Chọn keep-alive thay vì ba kết nối riêng là có chủ đích: nó cho một flow có **đủ bốn loại số** cần
kiểm trong một bản ghi — hai chiều không đối xứng (request ngắn, response dài), payload lẫn packet
trơn, cả bốn cờ TCP, và một `duration` khác 0. Ba kết nối riêng thì mỗi flow chỉ có vài packet và
không chỗ nào để sai.

Ca này cũng là chỗ **kiểm lại bằng công cụ bên ngoài** (NFR-19). Mọi con số ở các ca trước đều do
code của bài tự tính rồi tự đọc lại — nếu định nghĩa "byte" hay "chiều" sai ngay từ đầu thì không
test nội bộ nào phát hiện được. `tshark -z conv,tcp` tính cùng đại lượng từ cùng tệp bằng một cài
đặt độc lập, nên hai bên khớp là bằng chứng mạnh hơn hẳn.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 80" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  curl -s -o /dev/null "http://10.20.0.10/" "http://10.20.0.10/index.html" "http://10.20.0.10/submit"
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T13_statistics/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T13_statistics
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log

# Đối chiếu — chạy trên HOST, không trong container (tshark không có trong image)
tshark -r TEST/T13_statistics/input.pcap -q -z conv,tcp
tshark -r TEST/T13_statistics/input.pcap -q -z conv,udp
```

Ba URL phải nằm trong **một** lệnh `curl`: gọi `curl` ba lần thì mỗi lần mở kết nối riêng, PCAP ra
ba phiên và ca test thành một bản T11 thứ hai.

## 3. Kết quả mong đợi

Điều kiện dừng T7.3: exit 0; chạy lại khớp **từng byte**; README có bảng so **số flow** và
**packet/byte từng chiều** giữa `flows.jsonl` và `tshark`; mọi chỗ lệch có lý do viết ra;
`duration_usec` = `last_seen_usec − start_time_usec` kiểm được bằng `python -c`.

Nhánh hỏng hay gặp:

- `byte_count` của ta < `tshark` → đang đếm `cap_len` (số byte **bắt được**) thay vì `wire_len` (độ
  dài gốc trên dây). Hai số này bằng nhau khi không bị cắt bởi snaplen, nên bug này **ẩn** cho tới
  khi gặp một PCAP bắt với `-s` nhỏ.
- `byte_count` của ta = tổng payload (879) → đang đếm byte tầng ứng dụng mà gọi tên là "byte"; cột
  `Bytes` của `tshark` là độ dài frame.
- hai chiều đảo nhau (`forward` = 6/1045) → endpoint A không phải nguồn của packet **đầu tiên**.
  `tshark` xếp cột `->` theo địa chỉ in trước, nên muốn so được thì hai bên phải cùng một quy ước.
- `duration_usec` = `close_time − start_time` → với ca này vẫn ra 1175 vì flow đóng ở packet cuối,
  nhưng T12 đã cho thấy hai công thức khác nhau (ở đó: 0 vs 3 000 000).

## 4. Kết quả thực tế

```
$ cat run.log
config={"max_active_flows":10000,...,"tcp.closed":120,"tcp.established":3600,"tcp.new":60,...}
processed=14 unknown=0 malformed=0
flows_created=1 flows_closed=1 close.end_of_run=1 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

```
$ tshark -r TEST/T13_statistics/input.pcap -q -z conv,tcp
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.10.0.10:35742           <-> 10.20.0.10:80                    6 1045 bytes       8 774 bytes      14 1819 bytes     0.000000000         0.0012
```

`conv,udp` in bảng rỗng — PCAP này không có packet UDP nào.

So từng con số:

| Đại lượng | `flows.jsonl` | `tshark -z conv,tcp` | Khớp |
|---|---|---|---|
| số flow / conversation | 1 | 1 | ✔ |
| endpoint | `10.10.0.10:35742` ↔ `10.20.0.10:80` | `10.10.0.10:35742 <-> 10.20.0.10:80` | ✔ |
| packet tổng | `packet_count` = 14 | Total Frames 14 | ✔ |
| byte tổng | `byte_count` = 1819 | Total Bytes 1819 | ✔ |
| packet chiều A→B | `forward_packet_count` = 8 | `->` Frames 8 | ✔ |
| byte chiều A→B | `forward_byte_count` = 774 | `->` Bytes 774 | ✔ |
| packet chiều B→A | `backward_packet_count` = 6 | `<-` Frames 6 | ✔ |
| byte chiều B→A | `backward_byte_count` = 1045 | `<-` Bytes 1045 | ✔ |
| thời lượng | `duration_usec` = 1175 | Duration 0.0012 | ✔ (làm tròn, §5) |

Bốn đại lượng `tshark` **không** in ra, kiểm bằng chính `output.jsonl`:

| Đại lượng | flow record | tổng lại từ 14 event | Khớp |
|---|---|---|---|
| byte tải | `payload_byte_count` = 879 | Σ `tcp.payload_len` = 879 | ✔ |
| `syn_count` | 2 | 2 event có cờ `SYN` | ✔ |
| `ack_count` | 13 | 13 event có cờ `ACK` | ✔ |
| `fin_count` / `rst_count` | 2 / 0 | 2 / 0 | ✔ |

```sh
python3 -c "
import json
r = json.load(open('TEST/T13_statistics/flows.jsonl'))
print(r['duration_usec'], r['last_seen_usec'] - r['start_time_usec'],
      r['duration_usec'] == r['last_seen_usec'] - r['start_time_usec'])
print(r['forward_packet_count'] + r['backward_packet_count'] == r['packet_count'],
      r['forward_byte_count'] + r['backward_byte_count'] == r['byte_count'])
"
```

```
1175 1175 True
True True
```

## 5. Hai chỗ lệch, và lý do

**(a) `Duration` 0,0012 vs `duration_usec` 1175.** `tshark` in 4 chữ số thập phân nên 0,001175 s
hiện thành `0.0012`. Không phải lệch về cách tính: lấy trực tiếp timestamp của packet 1 và packet 14
(`0.000000` và `0.001175`) thì ra đúng 1175 µs. Ta giữ micro giây nguyên vì đó là độ phân giải của
PCAP cổ điển (Phụ lục D) — làm tròn ở tầng ghi bằng chứng là mất thông tin không lấy lại được.

**(b) `tshark` cắt phiên theo SYN, ta cắt theo ngưỡng im lặng.** Chỗ này không thấy được trên PCAP
của T13 (nó chỉ có một phiên), nên đo trên PCAP của T12 — hai SYN cùng 5-tuple cách nhau 3 s:

| Lần chạy | số flow / conversation |
|---|---|
| ta, ngưỡng mặc định (`tcp.new` = 60 s) | **1** flow, `packet_count` = 2 |
| ta, `--set tcp.new=1` | **2** flow (`idle_new` + `end_of_run`) |
| `tshark -z conv,tcp` | **2** conversation (`tcp.stream` = 0 và 1) |

Hai bên dùng **tiêu chí khác nhau**, không phải một bên sai:

- `tshark` cắt khi thấy một SYN mới trên 5-tuple đã có stream (`[TCP Port numbers reused]` trong
  danh sách packet). Nó đọc hết tệp nên luôn có thể nhìn lại.
- Ta cắt khi flow im lặng quá ngưỡng của **trạng thái** nó (REQ-33.1). IDS chạy trực tiếp không được
  giữ một ô trong bảng vô hạn chỉ để chờ xem có SYN nào quay lại — bảng sẽ đầy, mà bảng đầy thì mất
  flow (xem §5 của README T11). Ngưỡng im lặng là cái giá phải trả để bảng có giới hạn.

Hệ quả đọc được: hai cách lệch nhau **theo cả hai hướng**. Một phiên dài im lặng lâu bị ta cắt thành
hai flow còn `tshark` giữ một conversation; một 5-tuple được dùng lại nhanh thì `tshark` cắt mà ta
gộp. Khi đối chiếu số flow với `tshark` trên traffic thật, phải so **từng conversation**, không so
mỗi con số tổng.

## 6. Nhận xét

- **`byte_count` lấy `wire_len`, không lấy `cap_len`** (`flow.py`: thiếu `wire_len` thì mới dùng
  `cap_len` **và** ghi `wire_len_missing` vào `reasons`). Đây chính là lý do con số khớp `tshark`:
  cột `Bytes` của nó là `frame.len`, tức độ dài gốc trên dây. Đếm `cap_len` thì mọi PCAP bắt với
  `-s 0` vẫn khớp, và chỉ sai khi gặp tệp bị cắt — loại bug chỉ hiện ra đúng lúc không ai muốn.
- **`payload_byte_count` là số *thêm*, không thay `byte_count`** (A13). 1819 − 879 = 940 byte header:
  14 packet × (14 Ethernet + 20 IPv4) = 476, cộng header TCP 20 byte × 14 = 280, cộng 184 byte option
  TCP (timestamp/MSS/SACK/WS trên các packet có `data_offset` > 5). Hai con số trả lời hai câu khác
  nhau: "tốn bao nhiêu băng thông" và "có bao nhiêu byte nội dung để luật phát hiện soi".
- **`ack_count` = 13 trên 14 packet.** Chỉ packet 1 (SYN thuần) không có cờ ACK; cả SYN+ACK và hai
  FIN+ACK đều cộng vào `ack_count` vì bộ đếm đếm **cờ**, không đếm vai trò (REQ-34.5). Đây cũng là
  đại lượng `tshark -z conv,tcp` không in, nên nó phải tự kiểm bằng `output.jsonl` — mỗi event mang
  `tcp.flags` của chính nó, cộng lại phải ra đúng bốn counter của flow.
- **Chiều của ta và cột của `tshark` trùng nhau là nhờ cùng một quy ước, không phải tình cờ.**
  `forward` = từ `endpoint_a` = nguồn của packet **đầu tiên** thấy được; `tshark` xếp cột `->` theo
  địa chỉ in trước, mà nó cũng in theo packet đầu. Với PCAP bắt giữa phiên, packet đầu có thể là
  chiều server → client, và lúc đó **cả hai** bên cùng đảo tên (đã thấy ở §5 README T07) — nên vẫn
  so được.
