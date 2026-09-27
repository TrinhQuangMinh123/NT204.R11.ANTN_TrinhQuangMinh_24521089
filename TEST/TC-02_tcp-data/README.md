# TC-02 — TCP data

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-5.4 (payload TCP vào event), REQ-5.3 (header dài theo `data_offset`), I-4 (base64 giải ngược đúng) |
| Task | T7.1 · Phase 7 |
| Ngày ghi | 2026-09-27 |
| Traffic | một `curl http://10.20.0.10/` từ `attacker`, **kèm một header 2000 byte** để segment dữ liệu lớn hẳn lên |
| Kết quả | 10 packet, `processed=10 unknown=0 malformed=0` |
| `md5sum input.pcap` | `3773733ece0980e4f93e6b71439a5e1b` |

## 1. Kịch bản

TC-01 đã chứng minh phần **cờ** của header TCP. TC-02 chứng minh phần còn lại: **payload**.

Traffic cố tình khác TC-01 ở một điểm — request mang thêm header `X-Filler` dài 2000 byte, nên
segment dữ liệu dài `2086` byte thay vì `74` byte. Chọn như vậy vì một payload lớn làm ba con số
độc lập nhau (`ipv4.total_length`, `tcp.data_offset`, `tcp.payload_len`) phải khớp nhau bằng phép
tính, chứ không "tình cờ đúng" như khi payload chỉ có vài chục byte.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-02_tcp-data
docker compose exec -T attacker timeout 12 tcpdump -i eth0 -U -w - \
    'tcp and host 10.20.0.10 and port 80' > $TC/input.pcap &
sleep 4
docker compose exec -T attacker sh -c \
    'F=$(printf "A%.0s" $(seq 1 2000)); curl -s -o /dev/null -H "X-Filler: $F" http://10.20.0.10/'
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

`printf "A%.0s" $(seq 1 2000)` sinh đúng 2000 chữ `A` — filler **tất định**, nên chạy lại lệnh này
cho ra một request giống hệt (chỉ khác port nguồn và timestamp do kernel chọn).

`-U` để `tcpdump` ghi từng packet, không đệm → file vẫn hợp lệ khi `timeout` gửi SIGTERM.
`run.log` chỉ giữ output của **chương trình**; dòng `Container … Creating` của Compose bị lọc bỏ vì
chứa id sinh ngẫu nhiên, sẽ làm bằng chứng không lặp lại được.

## 3. Kết quả mong đợi

Điều kiện dừng của T7.1: `output.jsonl` có ít nhất một dòng với `payload_len` > 0 và `payload_b64`
khác `""`.

## 4. Kết quả thực tế

```sh
$ grep -o '"payload_len":[0-9]*' TEST/TC-02_tcp-data/output.jsonl | sort | uniq -c
      8 "payload_len":0
      1 "payload_len":2086
      1 "payload_len":239
$ cat TEST/TC-02_tcp-data/run.log
processed=10 unknown=0 malformed=0
```

Hai dòng có payload; `payload_b64` của chúng dài 2784 và 320 ký tự (khác `""`) → **đạt**.

## 5. Toàn bộ 10 packet

| # | Chiều | `flags` | `data_offset` | `total_length` | `payload_len` | Nội dung payload |
|---|---|---|---|---|---|---|
| 1 | attacker → victim | `["SYN"]` | 10 | 60 | 0 | — |
| 2 | victim → attacker | `["SYN","ACK"]` | 10 | 60 | 0 | — |
| 3 | attacker → victim | `["ACK"]` | 8 | 52 | 0 | — |
| 4 | attacker → victim | `["PSH","ACK"]` | 8 | **2138** | **2086** | `GET / HTTP/1.1` + 4 header (có `X-Filler`) |
| 5 | victim → attacker | `["ACK"]` | 8 | 52 | 0 | — (ack nhảy đúng 2086) |
| 6 | victim → attacker | `["PSH","ACK"]` | 8 | 291 | **239** | `HTTP/1.1 200 OK` + 8 header + body 11 byte |
| 7 | attacker → victim | `["ACK"]` | 8 | 52 | 0 | — (ack nhảy đúng 239) |
| 8 | attacker → victim | `["FIN","ACK"]` | 8 | 52 | 0 | — |
| 9 | victim → attacker | `["FIN","ACK"]` | 8 | 52 | 0 | — |
| 10 | attacker → victim | `["ACK"]` | 8 | 52 | 0 | — |

### 5.1 `payload_len` không phải là một con số đọc từ header

Không có trường nào trong TCP nói độ dài payload — nó là **hiệu** của ba con số ở hai tầng khác nhau:

```
payload_len = total_length - ihl*4 - data_offset*4
packet 4:   2086 = 2138 - 5*4 - 8*4      ✓
packet 6:    239 =  291 - 5*4 - 8*4      ✓
```

Nếu parser giả định header TCP 20 byte (`data_offset` 5) thì packet 4 ra `2098` byte payload, trong
đó 12 byte đầu là **options** (timestamp) bị đọc lẫn vào dữ liệu ứng dụng. Sai này im lặng: vẫn ra
bytes, không lỗi nào báo — nên nó chỉ lộ ra ở phép tính trên.

### 5.2 Chứng minh độc lập bằng `seq`/`ack` của bên kia

`seq` của TCP đếm theo byte, nên bên nhận phải `ack` đúng `seq + payload_len`:

```
packet 4: seq=2847186603 + 2086 = 2847188689 = ack của packet 5   ✓
packet 6: seq= 623595339 +  239 =  623595578 = ack của packet 7   ✓
```

Đây là bằng chứng do **victim và kernel** tạo ra, không phải do parser tự nói về mình.

### 5.3 base64 giải ngược ra đúng bytes (I-4)

```python
>>> d = base64.b64decode(rows[3]["tcp"]["payload_b64"])
>>> len(d)
2086
>>> d[:58]
b'GET / HTTP/1.1\r\nHost: 10.20.0.10\r\nUser-Agent: curl/8.14.1'
>>> d.count(b"A"), d.endswith(b"\r\n\r\n")
(2002, True)
```

2002 chữ `A` = 2000 của filler + 2 trong `Accept` và `User-Agent`. Payload kết thúc bằng `CRLFCRLF`
→ không mất byte cuối, không thừa byte đệm.

## 6. Nhận xét

- **`total_length` = 2138 > MTU 1500 mà packet vẫn đi được.** Đây không phải lỗi: `tcpdump` chạy
  trên **chính máy gửi**, ở điểm nằm **trước** khi kernel chia buffer thành các segment vừa MTU
  (TCP segmentation offload / GSO). Cùng họ với lý do `idps/decode/ipv4.py` **không** kiểm header
  checksum — packet bắt trên máy gửi có checksum chưa được NIC điền (rủi ro R1 trong design §11.1).
  Muốn thấy request bị chia thành hai segment thật thì phải bắt trên `int0` của sensor (phía sau
  điểm segment hoá), không phải trên `eth0` của attacker.
- Parser HTTP đọc trọn request trong **một** packet nên `incomplete=false`. Ca `incomplete=true`
  (request nằm vắt qua hai segment) không dựng được bằng lab ở điểm bắt này, nên nó được kiểm bằng
  packet dựng tay trong `tests/test_http.py` (ba mức chưa hoàn chỉnh).
- 8/10 packet có `payload_len=0`: đó là các packet **chỉ có ý nghĩa điều khiển** (handshake, ack,
  đóng kết nối). Chúng vẫn là event đầy đủ khoá — `app_proto` là `null` chứ không phải `"UNKNOWN"`,
  vì "không có dữ liệu" khác "có dữ liệu mà không nhận ra" (REQ-15.4).
- Port nguồn (`35680` ở lần ghi này) do kernel của attacker chọn nên **mỗi lần bắt lại sẽ khác**;
  `input.pcap` đã commit là bằng chứng cố định, `output.jsonl` sinh lại từ chính nó thì giống hệt
  từng byte (V7.1).
