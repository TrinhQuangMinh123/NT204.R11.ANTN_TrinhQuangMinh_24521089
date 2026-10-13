# T08 — Flow hai chiều

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-30.1 (hai chiều vào cùng một flow), REQ-30.4 (`direction` forward/backward), REQ-34.3–34.4 (thống kê theo chiều), Phụ lục K T08 |
| Task | T6.3 · Phase 6 (bài 2) |
| Ngày ghi | 2026-10-13 |
| Traffic | một `curl` POST `/submit` (body `user=alice&role=admin`) từ `attacker` tới `victim:80` |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0`, 1 flow, exit 0 |
| `md5sum input.pcap` | `30292b36a283c9d4090647bde8d6e695` |

## 1. Kịch bản

Dùng POST chứ không dùng GET như T07 vì ca này cần **cả hai chiều đều có payload**: request mang
171 byte, response mang 163 byte. Với GET thì chiều đi chỉ có dòng request ngắn và phần còn lại là
ACK trơn — vẫn chứng minh được `direction`, nhưng không chứng minh được `payload_byte_count` cộng từ
cả hai chiều, mà đó mới là chỗ dễ viết sai (chỉ đếm chiều gửi).

Tính chất phải chứng minh: 10 packet của phiên, dù nguồn/đích đảo nhau, nằm trong **một** `flow_id`,
và mỗi packet biết mình thuộc chiều nào.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 80" > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  curl -s -o /dev/null -d "user=alice&role=admin" "http://10.20.0.10/submit"
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T08_bidirectional-flow/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T08_bidirectional-flow
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

## 3. Kết quả mong đợi

Điều kiện dừng T6.3: exit 0; chạy lại khớp **từng byte**; mọi event có **cùng** `flow.flow_id`; có cả
`direction` = `forward` và `backward`; `flows.jsonl` có `forward_packet_count` > 0 và
`backward_packet_count` > 0, và `forward_* + backward_* = tổng`.

Nhánh hỏng hay gặp:

- `flows.jsonl` có **hai** dòng, mỗi dòng một chiều → khoá flow dùng `(src, dst)` nguyên thứ tự thay
  vì sắp xếp hai endpoint; đây là lỗi làm mọi thống kê hai chiều mất nghĩa.
- mọi event đều `forward` → `direction` so với `src_ip` của *packet hiện tại* chứ không so với
  `endpoint_a` đã chốt của flow.
- `forward_byte_count + backward_byte_count` ≠ `byte_count` → có nhánh cộng vào tổng mà quên cộng
  vào chiều (hoặc ngược lại); hay gặp nhất ở packet malformed.

## 4. Kết quả thực tế

```
$ cat run.log
processed=10 unknown=0 malformed=0
flows_created=1 flows_closed=1 close.end_of_run=1 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

Mười event, `flow.flow_id` = `1` ở **cả** mười, `direction` 6 forward / 4 backward:

| # | `direction` | `tcp.flags` | `tcp.payload_len` | `app.kind` |
|---|---|---|---|---|
| 1 | forward | `SYN` | 0 | — |
| 2 | backward | `SYN`, `ACK` | 0 | — |
| 3 | forward | `ACK` | 0 | — |
| 4 | forward | `PSH`, `ACK` | 171 | `request` (POST /submit) |
| 5 | backward | `ACK` | 0 | — |
| 6 | backward | `PSH`, `ACK` | 163 | `response` (200) |
| 7 | forward | `ACK` | 0 | — |
| 8 | forward | `FIN`, `ACK` | 0 | — |
| 9 | backward | `FIN`, `ACK` | 0 | — |
| 10 | forward | `ACK` | 0 | — |

Flow record:

```
flow_id=1  protocol=TCP  application_protocol=HTTP
endpoint_a=10.10.0.10:52330   endpoint_b=10.20.0.10:80
packet_count=10   byte_count=1010
forward_packet_count=6  forward_byte_count=575
backward_packet_count=4 backward_byte_count=435
payload_byte_count=334  state=CLOSED  midstream=false  close_reason=end_of_run
```

Ba phép cộng kiểm được bằng tay: `6 + 4 = 10` · `575 + 435 = 1010` · `171 + 163 = 334`.

## 5. Nhận xét

- **Hai chiều vào một ô bằng cách sắp thứ tự khoá.** Khoá flow là
  `(protocol, min(endpoint), max(endpoint))` với endpoint là tuple `(ip, port)`. Thứ tự này không cần
  có nghĩa gì — chỉ cần là **một** thứ tự toàn phần, để A→B và B→A luôn cho cùng một khoá. Nếu khoá
  giữ nguyên `(src, dst)` thì mỗi phiên tách làm hai và `backward_packet_count` của cả hai nửa đều
  bằng 0.
- **`direction` so với `endpoint_a` của flow, không so với vai client/server.** `endpoint_a` là nguồn
  của packet **đầu tiên** thấy được; mọi packet sau đó có `src` khớp `endpoint_a` là `forward`, còn
  lại là `backward`. Hệ quả cố ý: cùng một phiên nhưng bắt từ giữa thì tên hai chiều đảo lại (xem
  README của T07 §5) — tracker không suy đoán ai là client, nó chỉ ghi lại cái nó thấy trước.
- **`direction` ghi lên event, không để module sau tự tính.** Module sau không giữ `endpoint_a` của
  flow, nên nếu không ghi sẵn thì nó phải đoán chiều từ port ("port nhỏ là server") — đoán đó sai
  ngay với traffic không dùng port chuẩn, mà bài 1 đã có TC-13 cho đúng trường hợp đó.
- **`byte_count` lấy `wire_len` chứ không lấy `cap_len`.** Hai giá trị này bằng nhau ở đây vì bắt với
  `-s 0`, nhưng khi capture cắt theo snaplen thì chỉ `wire_len` còn nói đúng khối lượng traffic đã đi
  qua dây (REQ-34.7).
