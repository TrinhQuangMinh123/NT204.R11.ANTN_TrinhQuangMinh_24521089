# T10 — Flow UDP (DNS query/response)

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-32.1 (flow UDP theo 5-tuple), REQ-32.2/32.4 (một trạng thái `ACTIVE`, không counter cờ TCP), REQ-32.3 (packet/byte hai chiều), Phụ lục K T10 |
| Task | T6.5 · Phase 6 (bài 2) |
| Ngày ghi | 2026-10-13 |
| Traffic | một `dig victim.lab A` từ `attacker` tới `victim:53` (dnsmasq) |
| Kết quả | 2 packet, `processed=2 unknown=0 malformed=0`, 1 flow UDP, exit 0 |
| `md5sum input.pcap` | `cd9ca5f1ebf97d2e08cf7b5825b1820b` |

## 1. Kịch bản

Hai packet là **toàn bộ** một "phiên" DNS: query đi, response về, hết. Ca này kiểm đúng chỗ UDP khác
TCP:

- UDP **không có kết nối**, nên không có bắt tay để suy ra trạng thái. Flow UDP chỉ có **một** trạng
  thái `ACTIVE` (REQ-32.2) — tracker không được bịa ra `ESTABLISHED`/`CLOSED` từ việc đã thấy chiều
  ngược hay chưa.
- Vẫn phải gom được hai chiều vào một flow: `dig` mở một port nguồn tạm (54543), dnsmasq trả lời từ
  53 về đúng port đó, nên 5-tuple đảo chiều — cùng cơ chế sắp thứ tự khoá như TCP.

Lọc `udp port 53` và dùng `+tries=1` để PCAP có **đúng** hai packet: nếu `dig` truyền lại thì số
packet đổi và con số trong README này không còn khớp.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "udp port 53" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  dig +short +tries=1 +timeout=3 @10.20.0.10 victim.lab A > /dev/null
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T10_dns-udp-flow/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T10_dns-udp-flow
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

## 3. Kết quả mong đợi

Điều kiện dừng T6.5: exit 0; chạy lại khớp **từng byte**; `flows.jsonl` có **một** dòng với
`protocol` = `UDP`, `state` = `ACTIVE`, `application_protocol` = `DNS`, `packet_count` = 2, mỗi chiều
1 packet, bốn counter cờ TCP = `0`, `midstream` = `null`.

Nhánh hỏng hay gặp:

- **hai** dòng flow → khoá flow không gom hai chiều, hoặc gom theo `(ip, port)` nguồn.
- `midstream` = `false` thay vì `null` → đang trả giá trị mặc định của TCP cho một flow UDP; `false`
  nghĩa là "đã thấy từ đầu phiên", một mệnh đề **không có nghĩa** với UDP.
- `syn_count`/`ack_count` ≠ 0 → nhánh đếm cờ chạy cho cả UDP, tức là đang đọc `tcp.flags` của một
  packet không có header TCP.
- `state` = `ESTABLISHED` → đang suy trạng thái kết nối từ việc đã thấy chiều ngược.

## 4. Kết quả thực tế

```
$ cat run.log
processed=2 unknown=0 malformed=0
flows_created=1 flows_closed=1 close.end_of_run=1 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

Hai event, cùng `flow_id` = `1`, `state` = `ACTIVE`, `reasons` = `[]`:

| # | `direction` | `udp.payload_len` | `app_proto` | nội dung DNS |
|---|---|---|---|---|
| 1 | forward | 51 | `DNS` | query `victim.lab` type `A` |
| 2 | backward | 55 | `DNS` | response `NOERROR`, 1 answer `10.20.0.10` ttl 300 |

Flow record:

```
flow_id=1  protocol=UDP  application_protocol=DNS
endpoint_a=10.10.0.10:54543  endpoint_b=10.20.0.10:53
packet_count=2  byte_count=190   payload_byte_count=106
forward: 1 packet / 93 byte      backward: 1 packet / 97 byte
syn_count=0 ack_count=0 fin_count=0 rst_count=0
state=ACTIVE  midstream=null  close_reason=end_of_run  duration_usec=255
```

`93 + 97 = 190` và `51 + 55 = 106`; chênh 42 byte giữa `byte_count` và `payload_byte_count` của mỗi
packet là header Ethernet (14) + IPv4 (20) + UDP (8).

## 5. Nhận xét

- **`midstream` là `null`, không phải `false`.** Trường này trả lời "có bắt được từ packet mở đầu
  phiên hay không", mà UDP không có packet mở đầu nào để so. Trả `false` là khẳng định một điều không
  đo được; `null` nói đúng "không áp dụng" (REQ-32.4). Cùng lý do đó, bốn counter cờ TCP vẫn có mặt
  trong record nhưng giữ `0` — tập khoá của flow record là **cố định** cho cả TCP và UDP, module sau
  không phải kiểm tra sự tồn tại của từng khoá.
- **Ngưỡng im lặng của UDP tra theo `backward_packet_count`, không theo `state`.** Vì `state` luôn là
  `ACTIVE` nên nó không phân biệt được gì; thứ phân biệt là đã có chiều ngược hay chưa: chưa có →
  `udp.new` (30 s), có rồi → `udp.established` (300 s). Một query DNS không ai trả lời là hình dạng
  đáng chú ý và nên rời bảng sớm, còn một phiên hai chiều thì được giữ lâu hơn.
- **`application_protocol` = `DNS` lấy từ packet đầu có `app_proto` thật rồi giữ nguyên.** Nếu một
  packet giữa phiên bị nhận nhầm giao thức thì tên của cả flow không nhảy theo (REQ-34.6).
- **`dns_names` của packet 2 có `victim.lab` hai lần** (một từ phần question, một từ phần answer).
  Đây là dữ liệu của Preprocessor, không phải lỗi trùng: nó liệt kê **mọi** tên xuất hiện trong
  packet, và việc một tên xuất hiện ở cả hai chỗ là thông tin thật của response.
