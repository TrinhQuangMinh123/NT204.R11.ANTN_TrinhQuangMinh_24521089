# T11 — Nhiều flow đồng thời

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-30.5 (nhiều flow song song, không gộp nhầm), REQ-33.5 + I-17 (bảng đầy → `table_full`), REQ-31.8 (flow sinh lại là `midstream`), Phụ lục K T11 |
| Task | T7.1 · V7.2 · Phase 7 (bài 2) |
| Ngày ghi | 2026-10-13 |
| Traffic | một phiên SMTP giữ mở suốt lần bắt, trong lúc đó chen một `curl` GET và một `dig` |
| Kết quả | 32 packet, `processed=32 unknown=0 malformed=0`, 3 flow, exit 0 |
| `md5sum input.pcap` | `12d6a74b5420a2593dbe865926b91ab1` |

## 1. Kịch bản

Ba phiên **lồng vào nhau**, không phải ba phiên nối tiếp:

| packet | phiên |
|---|---|
| 1–13 | SMTP `43220 → 25`: bắt tay, `EHLO`, bốn dòng banner của victim |
| 14–23 | HTTP `51998 → 80`: cả vòng đời, kể cả FIN hai chiều |
| 24–25 | DNS `50331 → 53` trên UDP |
| 26–32 | SMTP `43220 → 25` **tiếp tục**: `QUIT`, `221 Bye`, FIN hai chiều |

Chỗ cần kiểm nằm ở packet 26: nó thuộc flow đã mở ở packet 1, nhưng giữa chúng có 12 packet của hai
phiên khác. Một tracker giữ "flow đang xử lý" làm biến duy nhất (lối viết tắt hay gặp) sẽ cho packet
26 vào flow HTTP hoặc mở flow mới — cả hai đều sai. Bảng tra theo khoá thì packet 26 tìm lại đúng ô
của nó bất kể đã có bao nhiêu phiên khác chen vào giữa.

Ba flow cũng khác nhau theo **ba kiểu** khác nhau, nên ca này kiểm đủ ba thành phần của khoá:

- flow 1 vs flow 2: cùng cặp IP, cùng `TCP`, khác **port** → khoá phải có port.
- flow 3 vs hai flow kia: cùng cặp IP, khác **giao thức transport** → khoá phải có `transport_proto`,
  không được gom `UDP 53` vào cùng ô với một phiên TCP cùng cặp IP.
- trong mỗi flow: hai chiều phải về **một** `flow_id` → khoá sắp thứ tự endpoint trước khi tra.

## 2. Lệnh tái hiện

```sh
docker compose up -d idps attacker victim

docker compose exec -T attacker sh -c '
  tcpdump -i eth0 -U -s 0 -Z root -w - "tcp port 25 or tcp port 80 or udp port 53" \
      > /tmp/cap.pcap 2>/tmp/tcpdump.err &
  TD=$!
  sleep 2
  { printf "EHLO attacker.lab\r\n"; sleep 2; printf "QUIT\r\n"; sleep 1; } | nc 10.20.0.10 25 > /dev/null &
  NC=$!
  sleep 1
  curl -s -o /dev/null "http://10.20.0.10/"
  dig +short +tries=1 +timeout=3 @10.20.0.10 victim.lab A > /dev/null
  wait $NC
  sleep 2
  kill -INT $TD; wait $TD'
docker compose exec -T attacker cat /tmp/cap.pcap > TEST/T11_concurrent-flows/input.pcap

export HOST_UID=$(id -u) HOST_GID=$(id -g)
TC=TEST/T11_concurrent-flows
docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap \
    -o $TC/output.jsonl --flow-output $TC/flows.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

Phiên SMTP chạy ở background (`&`) và `nc` chỉ nhận dòng từ một khối `{ … }` có `sleep` ở giữa: đó là
cách giữ kết nối mở trong lúc `curl` và `dig` chạy. Nếu gửi `EHLO` và `QUIT` liền nhau thì phiên SMTP
đóng trước khi hai lệnh kia bắt đầu — PCAP vẫn có 3 flow nhưng chúng **nối tiếp**, và packet 26 không
còn tồn tại để kiểm chuyện cần kiểm.

Chạy lại recipe cho một PCAP khác (port tạm của `nc`/`curl`/`dig` do kernel cấp, timestamp mới) nhưng
cùng 32 packet và cùng bốn khối ở §1. Phần khớp **từng byte** là lần chạy pipeline trên
`input.pcap` đã commit, không phải lần bắt gói.

## 3. Kết quả mong đợi

Điều kiện dừng T7.1: exit 0; chạy lại khớp **từng byte**; `flows.jsonl` có ≥ 2 dòng `flow_id` khác
nhau; mỗi event thuộc đúng flow của nó — với mỗi `flow_id`, tập 5-tuple của các event mang `flow_id`
đó chỉ có **một** cặp endpoint (đảo chiều thì vẫn là cặp đó).

Nhánh hỏng hay gặp:

- `flows.jsonl` có **1** dòng, `packet_count` = 32 → khoá flow chỉ gồm cặp IP, ba phiên dồn một ô.
- `flows.jsonl` có **4** dòng, hai dòng SMTP cùng port → packet 26 mở flow mới, tức là tra bảng theo
  "flow gần nhất" chứ không theo khoá.
- flow 3 là `TCP` hoặc có `packet_count` = 22 → `UDP 53` bị gom vào ô của một phiên TCP cùng cặp IP.
- một flow có hai cặp endpoint khác nhau → chuẩn hoá khoá sai chiều, hai phiên khác port lọt chung ô.

## 4. Kết quả thực tế

```
$ cat run.log
config={"max_active_flows":10000,...,"tcp.closed":120,"tcp.established":3600,"tcp.new":60,...}
processed=32 unknown=0 malformed=0
flows_created=3 flows_closed=3 close.end_of_run=3 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

Ba dòng `flows.jsonl`:

| `flow_id` | `protocol` | `application_protocol` | endpoint | packet (fwd/bwd) | byte (fwd/bwd) | `state` |
|---|---|---|---|---|---|---|
| 1 | TCP | SMTP | `10.10.0.10:43220` ↔ `10.20.0.10:25` | 20 (11/9) | 1444 (759/685) | `CLOSED` |
| 2 | TCP | HTTP | `10.10.0.10:51998` ↔ `10.20.0.10:80` | 10 (6/4) | 989 (478/511) | `CLOSED` |
| 3 | UDP | DNS | `10.10.0.10:50331` ↔ `10.20.0.10:53` | 2 (1/1) | 190 (93/97) | `ACTIVE` |

`20 + 10 + 2 = 32` = `processed`: mỗi packet vào đúng một flow, không packet nào bị đếm hai lần hay
bị bỏ.

Kiểm "không gộp nhầm" bằng cách đọc `output.jsonl`:

```sh
python3 - <<'EOF'
import json, collections
ev = [json.loads(l) for l in open('TEST/T11_concurrent-flows/output.jsonl')]
pairs = collections.defaultdict(set); dirs = collections.defaultdict(collections.Counter)
for e in ev:
    f = e['flow']
    pairs[f['flow_id']].add(frozenset({(e['src_ip'], e['src_port']), (e['dst_ip'], e['dst_port'])}))
    dirs[f['flow_id']][f['direction']] += 1
for fid in sorted(pairs):
    print(fid, len(pairs[fid]), sorted(next(iter(pairs[fid]))), dict(dirs[fid]))
EOF
```

```
1 1 [('10.10.0.10', 43220), ('10.20.0.10', 25)] {'forward': 11, 'backward': 9}
2 1 [('10.10.0.10', 51998), ('10.20.0.10', 80)] {'forward': 6, 'backward': 4}
3 1 [('10.10.0.10', 50331), ('10.20.0.10', 53)] {'forward': 1, 'backward': 1}
```

Cột thứ hai là **số** cặp endpoint khác nhau trong một `flow_id`, đều bằng `1`. Số đếm hai chiều
khớp `forward_packet_count` / `backward_packet_count` của flow record tương ứng.

Chuỗi `flow.state` trên các event của flow 1 là `HANDSHAKE` ×2 → `ESTABLISHED` ×14 → `CLOSING` ×3 →
`CLOSED`; mười hai event của flow 2 và flow 3 nằm **xen giữa** đoạn `ESTABLISHED` đó mà không làm đổi
trạng thái flow 1 — trạng thái thuộc về ô trong bảng, không thuộc về tracker.

## 5. Bảng active đầy — `max_active_flows=2` (V7.2)

```sh
export HOST_UID=$(id -u) HOST_GID=$(id -g)
docker compose run --rm idps-offline python main.py \
    --pcap TEST/T11_concurrent-flows/input.pcap \
    -o tmp/v72-out.jsonl --flow-output tmp/v72-flows.jsonl --set max_active_flows=2
```

```
config={"max_active_flows":2,...}
processed=32 unknown=0 malformed=0
flows_created=4 flows_closed=4 close.table_full=2 close.end_of_run=2 decode_errors=0 preprocess_errors=0 flow_errors=0
```

| `flow_id` | phiên | packet | `state` | `close_reason` | `midstream` |
|---|---|---|---|---|---|
| 1 | SMTP | 13 | `ESTABLISHED` | `table_full` | `false` |
| 2 | HTTP | 10 | `CLOSED` | `table_full` | `false` |
| 3 | DNS | 2 | `ACTIVE` | `end_of_run` | `null` |
| 4 | SMTP (sinh lại) | 7 | `CLOSED` | `end_of_run` | `true` |

Đọc theo thứ tự packet: tới packet 24 (DNS) bảng đã có SMTP và HTTP, cần ô thứ ba → loại flow **lâu
không có packet nhất**, lúc đó là SMTP (packet cuối của nó là số 13). Tới packet 26 (`QUIT` của SMTP)
bảng có HTTP và DNS, lại cần ô → loại HTTP, rồi mở flow 4 cho đoạn SMTP còn lại.

- `13 + 10 + 2 + 7 = 32`: **không mất flow record nào** và không mất event nào. Flow bị loại được
  **xuất ra** `flows.jsonl` trước khi rời bảng (I-17), nên 32 packet vẫn truy được về 4 bản ghi.
- `close_reason` = `table_full` phân biệt được với `end_of_run` và `idle_*`: đọc log đã commit là
  biết flow kết thúc vì bảng chật, không phải vì phiên đã xong — hai chuyện dẫn tới cách sửa khác
  nhau (tăng `max_active_flows` vs không phải làm gì).
- Flow 1 giữ `state` = `ESTABLISHED`: nó bị loại **giữa phiên**, chưa thấy FIN nào. Trạng thái trong
  record là trạng thái thật lúc rời bảng, không bị ghi đè thành `CLOSED` chỉ vì record đã chốt sổ.
- Flow 4 có `midstream` = `true` mà không cần PCAP đặc biệt: packet đầu tiên nó thấy là `QUIT`
  (`PSH+ACK`), không phải SYN thuần — đúng định nghĩa REQ-31.8. Đây cũng là cái giá của việc loại
  flow sớm: một phiên bị cắt thành hai bản ghi, và `midstream` = `true` là dấu để biết bản ghi thứ
  hai không phải một kết nối mới.

Hai tệp trong `tmp/` là tạm, không commit.

## 6. Nhận xét

- **`flow_id` cấp tăng dần theo thứ tự flow được tạo, không theo port hay thời điểm kết thúc.**
  Flow 2 (HTTP) kết thúc trước flow 1 (SMTP) nhưng vẫn mang số lớn hơn. Số này chỉ để nối event với
  flow record trong **một** lần chạy — không phải định danh bền giữa các lần chạy.
- **`close_time` của cả ba flow ở §4 đều giống nhau** (`01:47:02.504030Z` — timestamp của packet
  cuối): chúng cùng bị đóng ở bước cuối lần chạy, không phải lúc phiên của chúng thật sự xong. Còn
  `last_seen` thì khác nhau, và `duration_usec` tính từ `last_seen − start_time` nên vẫn đúng với
  phiên (flow 2 chỉ 757 µs, flow 1 gần 3 s). Lấy `close_time − start_time` làm thời lượng là một
  nhánh sai dễ gặp.
- **Flow 1 và 2 ở §4 có `state` = `CLOSED` nhưng `close_reason` = `end_of_run`.** `CLOSED` là trạng
  thái của kết nối (FIN hai chiều + ACK đã thấy); `close_reason` là lý do bản ghi rời bảng. Flow đã
  `CLOSED` vẫn nằm trong bảng thêm `tcp.closed` = 120 s để một packet đến muộn còn tra được về đúng
  phiên, nên PCAP chỉ dài 3 s thì nó vẫn còn ở đó tới cuối lần chạy.
