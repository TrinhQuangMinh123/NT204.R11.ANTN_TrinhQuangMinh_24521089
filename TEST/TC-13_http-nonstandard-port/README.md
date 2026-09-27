# TC-13 — HTTP trên port không chuẩn (điểm thưởng)

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-11.1 (HTTP trên port lạ vẫn được gán HTTP), REQ-10.2 (port khớp nhưng payload không khớp → không gán), REQ-10.4 (`detect_method`) |
| Task | T7.5 · Phase 7 |
| Ngày ghi | 2026-09-27 |
| Traffic | `curl http://10.20.0.10:8081/` **và** một payload không phải HTTP gửi vào port **80** bằng `nc` |
| Kết quả | 20 packet, `processed=20 unknown=0 malformed=0` |
| `md5sum input.pcap` | `9b64d9119a54488dc61d8f7710a96892` |

## 1. Kịch bản

ADR-5 nói: **port quyết định THỨ TỰ THỬ, payload quyết định KẾT QUẢ.** Một câu có hai nửa, nên file
này chứa hai phiên để kiểm cả hai nửa trong **cùng một** bằng chứng:

| Phiên | Port | Payload | Nửa nào của ADR-5 |
|---|---|---|---|
| 1 | 8081 (không chuẩn) | HTTP thật | port **không** khớp mà vẫn gán HTTP → REQ-11.1 |
| 2 | 80 (chuẩn) | `NOTHTTP junk\r\n` | port khớp mà **không** gán HTTP → REQ-10.2 |

Nếu chỉ có phiên 1 thì chưa loại được cách cài đặt "gán HTTP cho mọi thứ nhìn giống text"; nếu chỉ có
phiên 2 thì chưa loại được cách cài đặt "chỉ xét port". Hai phiên cạnh nhau loại cả hai.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-13_http-nonstandard-port
docker compose exec -T attacker tcpdump -i eth0 -U -c 20 -w - \
    'tcp and host 10.20.0.10 and (port 80 or port 8081)' > $TC/input.pcap &
CAP=$!
sleep 3
docker compose exec -T attacker curl -s -o /dev/null http://10.20.0.10:8081/
sleep 1
docker compose exec -T attacker sh -c "printf 'NOTHTTP junk\r\n' | nc -w2 10.20.0.10 80"
wait $CAP
```

```sh
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl 2>&1 | tee $TC/run.log
```

Port 8081 lấy từ Phụ lục E (**không** dùng 8080 — C-16); nginx của victim listen cả 80 và 8081 với
cùng một `server` block, nên hai phiên chỉ khác nhau ở **port**, không khác nhau ở nội dung.
`nc -w2` để nc tự đóng sau 2 giây không có dữ liệu mới.

## 3. Kết quả mong đợi

Điều kiện dừng của T7.5: dòng có `"dst_port":8081` mang `"app_proto":"HTTP"` và
`"detect_method":"payload"`.

## 4. Kết quả thực tế

```sh
$ grep '"dst_port":8081' TEST/TC-13_http-nonstandard-port/output.jsonl \
      | grep -o '"app_proto":"[^"]*","detect_method":"[^"]*"'
"app_proto":"HTTP","detect_method":"payload"
$ cat TEST/TC-13_http-nonstandard-port/run.log
processed=20 unknown=0 malformed=0
```

→ **đạt**. Bốn packet mang payload, xếp cạnh nhau:

```
packet  4: "src_port":43982,"dst_port":8081,"app_proto":"HTTP",   "detect_method":"payload"
packet  6: "src_port":8081, "dst_port":43982,"app_proto":"HTTP",   "detect_method":"payload"
packet 14: "src_port":36188,"dst_port":80,  "app_proto":"UNKNOWN","detect_method":null
packet 16: "src_port":80,   "dst_port":36188,"app_proto":"HTTP",   "detect_method":"port+payload"
```

## 5. Đọc bốn dòng trên theo thuật toán của `detect()`

| Packet | Payload (24 byte đầu) | Ứng viên khớp port? | Chữ ký khớp? | Kết quả |
|---|---|---|---|---|
| 4 | `GET / HTTP/1.1\r\nHost: 10` | không (8081 ∉ `ports`) | có (`GET `) | `HTTP` · `payload` |
| 6 | `HTTP/1.1 200 OK\r\nServer:` | không | có (`HTTP/1.`) | `HTTP` · `payload` |
| 14 | `NOTHTTP junk\r\n` | **có** (80) | **không** | `UNKNOWN` · `null` |
| 16 | `HTTP/1.1 400 Bad Request` | có (80) | có | `HTTP` · `port+payload` |

- **Packet 4 và 6** chứng minh REQ-11.1: HTTP chạy ở 8081 vẫn được nhận, và vì nhóm "khớp port" rỗng
  nên nó được tìm thấy ở nhóm thứ hai → `detect_method` ghi lại đúng rằng kết luận đến **chỉ từ
  payload**. Hai chiều đều được nhận vì `detect()` xét **cả** `sport` lẫn `dport`; nếu chỉ xét
  `dport` thì packet 6 (`sport=8081`) sẽ thành `UNKNOWN`.
- **Packet 14** chứng minh REQ-10.2: payload đi **tới** port 80, ứng viên HTTP được thử **đầu tiên**,
  nhưng `matches_http()` trả `False` (không mở đầu bằng `<METHOD> ` hay `HTTP/1.`) nên không gán.
  Một shell ngược nghe ở port 80 cũng ra kết quả này — đó chính là mục đích.
- **Packet 16** là lời đáp của nginx (`400 Bad Request`): nginx **cũng** không hiểu payload đó, nhưng
  nó trả lời bằng HTTP hợp lệ, nên event của packet đáp lại là HTTP với `port+payload`. Một file bằng
  chứng chứa cả `UNKNOWN` và `HTTP` trên **cùng một cặp port** cho thấy `app_proto` đi theo từng
  packet, không đi theo port.

## 6. `UNKNOWN` không phải lỗi

```sh
$ grep -c '"status":"ok"' TEST/TC-13_http-nonstandard-port/output.jsonl
20
$ grep -c '"app_proto":"UNKNOWN"' TEST/TC-13_http-nonstandard-port/output.jsonl
1
```

Packet 14 có `app_proto="UNKNOWN"` nhưng `status="ok"` và `errors` rỗng, `app` là `null` (ADR-14).
Lý do: `"UNKNOWN"` ở tầng ứng dụng nghĩa là "bài 1 mới cài ba giao thức, payload này không thuộc ba
giao thức đó" — dữ liệu không sai, chương trình không sai. Khác hẳn `network_proto="UNKNOWN"` và
`transport_proto="UNKNOWN"`, hai khoá **có** làm `status` thành `"unknown"` (danh sách `_UNKNOWN_KEYS`
trong `idps/core/event.py`) vì ở đó có một con số trong header nói rõ giao thức gì mà chương trình
chưa đọc được.

## 7. Nhận xét

- `detect_method` là `null` ở packet 14: không có **phương pháp nào** dẫn tới kết luận `UNKNOWN` —
  đó là kết quả của việc thử hết mà trượt. Cố tình không có giá trị `"port"` đơn lẻ trong
  `detect_method`, vì REQ-10.2 không cho phép kết luận khi chưa xem payload.
- Ba packet HTTP ở đây (`payload`, `payload`, `port+payload`) cộng với TC-04 (`port+payload` cả hai
  chiều) phủ **cả hai nhánh** của `detect()` bằng traffic thật — cùng kết luận với V6.1 nhưng trên
  bằng chứng dành riêng.
- Nếu đổi `ports=(80,)` trong `APP_PROTOCOLS` thành `ports=(80, 8081)` thì packet 4 và 6 sẽ đổi sang
  `port+payload`, còn kết quả `HTTP` thì **không** đổi. Đây là cách kiểm nhanh rằng port thật sự chỉ
  ảnh hưởng tới *thứ tự thử*. (Không làm thế trong bài: Q-D7 đã chốt **không** thêm port chuẩn, vì
  8081 phải là ca non-standard cho đúng test case này.)
