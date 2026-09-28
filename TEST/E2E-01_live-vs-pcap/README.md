# E2E-01 — Live capture vs PCAP replay

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-3.2 (cùng một chuỗi packet đưa vào qua live và qua PCAP → event giống nhau, miễn trường phụ thuộc nguồn), REQ-18.4 (chế độ `--interface` trong container sensor bắt được traffic attacker ↔ victim), R1 (design §11: Scapy có thể **dựng lại** bytes thay vì trả bytes trên dây) |
| Task | T11.1 · Phase 11 |
| Ngày ghi | 2026-09-28 |
| Traffic | HTTP GET + HTTP POST + DNS query + phiên SMTP, attacker `10.10.0.10` → victim `10.20.0.10`, đi xuyên sensor |
| Kết quả | 42 packet, hai đường cùng ra `processed=42 unknown=0 malformed=0`, **0 dòng khác biệt** |
| `md5sum input.pcap` | `4cd3335efbe6098d5117f89e14790e81` |

## 1. Kịch bản

Đây là test case duy nhất trong repo chạy **chế độ live** (`--interface`). Mười ba TC trước đều đi đường
PCAP; cái này kiểm chứng rằng **hai đường cho cùng một kết quả**, tức khẳng định của thiết kế D1 ("một
pipeline duy nhất cho live và PCAP, hai nguồn chỉ khác nhau ở adapter") là đúng chứ không phải là lời hứa.

Cách đo: cho **hai máy nghe cùng lúc trên cùng một interface** `int0` của sensor.

```
attacker 10.10.0.10                sensor                        victim 10.20.0.10
       eth0 ─── net_ext ─── ext0 ── kernel forward ── int0 ─── net_int ─── eth0
                                                      │
                                       ┌──────────────┴──────────────┐
                                 main.py --interface int0      tcpdump -i int0
                                 (AF_PACKET của Scapy)         (AF_PACKET của libpcap)
                                       │                             │
                                  live.jsonl                    input.pcap
                                       │                             │
                                       │              main.py --pcap input.pcap
                                       │                             │
                                       └────── so sánh ──────── pcap.jsonl
```

Hai tap AF_PACKET trên cùng một interface nhận **cùng một tập frame** — đó là điều kiện tiên quyết để
phép so sánh nói về *parser* chứ về vị trí đặt máy nghe. Vì sao không đặt `tcpdump` trong container
attacker như kế hoạch ban đầu của `tasks.md`: xem §5.

Traffic gồm bốn phiên, mỗi phiên cách nhau 1 giây:

| # | Gửi đi | Giao thức ứng dụng nó sinh ra |
|---|---|---|
| 1 | `curl http://10.20.0.10/` | HTTP GET + response 200 |
| 2 | `curl -X POST -d 'user=e2e&token=abc' http://10.20.0.10/submit` | HTTP POST (có body) + response 200 |
| 3 | `dig @10.20.0.10 www.victim.lab A` | DNS query + response (UDP) |
| 4 | `printf 'EHLO…MAIL FROM…QUIT' \| nc 10.20.0.10 25` | SMTP: 1 segment lệnh + 6 reply |

Bốn phiên chọn đủ **ba giao thức ứng dụng** của bài (HTTP, DNS, SMTP) và đủ **hai giao thức transport**
(TCP, UDP), nên mọi parser trong `idps/decode/` đều được chạy ở cả hai đường.

## 2. Lệnh tái hiện

```sh
TC=TEST/E2E-01_live-vs-pcap
export HOST_UID=$(id -u) HOST_GID=$(id -g)
IDPS=$(docker compose ps -q idps)
: > $TC/run.log

# 1. Sensor bắt live trên int0. PID ghi ra file để dừng đúng tiến trình python.
docker compose exec -T idps sh -c \
    'python main.py --interface int0 -o /tmp/live.jsonl & echo $! > /tmp/live.pid; wait' \
    > /tmp/live.out 2>&1 &
LIVE=$!

# 2. tcpdump chạy trong ĐÚNG network namespace của sensor → cùng interface int0.
docker run --rm --name e2e-tcpdump --network "container:$IDPS" \
    --cap-drop ALL --cap-add NET_RAW --cap-add SETUID --cap-add SETGID \
    idps-attacker tcpdump -i int0 -p -s 65535 -U -w - > $TC/input.pcap 2>/dev/null &
CAP=$!

sleep 4

# 3. Traffic: HTTP GET, HTTP POST, DNS, SMTP
docker compose exec -T attacker sh -c '
    curl -s -o /dev/null http://10.20.0.10/ ;                                      sleep 1
    curl -s -o /dev/null -X POST -d "user=e2e&token=abc" http://10.20.0.10/submit ; sleep 1
    dig +short @10.20.0.10 www.victim.lab A > /dev/null ;                           sleep 1
    printf "EHLO e2e.lab\r\nMAIL FROM:<probe@e2e.lab>\r\nQUIT\r\n" \
        | nc -w 3 10.20.0.10 25 > /dev/null'

sleep 4

# 4. Dừng tcpdump trước, rồi SIGTERM cho sensor, rồi lấy file ra khỏi container.
docker stop -t 5 e2e-tcpdump > /dev/null
wait $CAP
docker compose exec -T idps sh -c 'kill -TERM $(cat /tmp/live.pid)'
wait $LIVE; live_code=$?
docker compose exec -T idps cat /tmp/live.jsonl > $TC/live.jsonl
sed 's/^/live /' /tmp/live.out >> $TC/run.log
echo "live exit=$live_code" >> $TC/run.log

# 5. Cùng chuỗi packet đó, lần này qua đường PCAP.
docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/pcap.jsonl > /tmp/pcap.out 2>&1
pcap_code=$?
grep -v '^ *Container ' /tmp/pcap.out | sed 's/^/pcap /' >> $TC/run.log
echo "pcap exit=$pcap_code" >> $TC/run.log

# 6. So sánh sau khi bỏ ba trường phụ thuộc lần chạy (§6).
STRIP='s/^{"schema_version":1,"packet_id":[0-9]*,"timestamp":"[^"]*","source":"[a-z]*",/{/'
sed "$STRIP" $TC/live.jsonl > /tmp/live.stripped
sed "$STRIP" $TC/pcap.jsonl > /tmp/pcap.stripped
diff /tmp/live.stripped /tmp/pcap.stripped
echo "diff lines=$(diff /tmp/live.stripped /tmp/pcap.stripped | wc -l)" >> $TC/run.log
```

Sáu chi tiết của khối lệnh, mỗi cái sửa một cách hỏng cụ thể:

- **`echo $! > /tmp/live.pid` rồi `kill -TERM` bằng một lệnh `exec` thứ hai.** `docker compose exec -T`
  **không** truyền tín hiệu vào tiến trình trong container: giết tiến trình client trên host chỉ đóng
  đường ống, `python` bên trong vẫn chạy và file `/tmp/live.jsonl` không bao giờ được đóng. Phải tự cầm
  PID. Cũng không dùng `timeout`: trên máy WSL2 này `timeout` không bắn tín hiệu (lý do đầy đủ ở
  `TC-02/README.md` §2). Vòng vo này đổi lại một điều có ích: nó chạy **đúng đường dừng của ADR-8**
  (SIGTERM → `on_sigterm` → `KeyboardInterrupt` → Runner đóng sink → in thống kê → exit 0), và
  `live exit=0` trong `run.log` là bằng chứng REQ-1.6/1.7.
- **`-p` (không promiscuous).** `LiveSource._open()` gọi `conf.L2listen(..., promisc=False)`. Nếu một tap
  bật promiscuous mà tap kia không, hai tap có thể thấy hai **tập frame khác nhau** (frame không gửi tới
  MAC của sensor chỉ tới được tap đang promiscuous) → phép so sánh biến thành phép so sánh hai máy nghe,
  không còn nói gì về parser.
- **`-s 65535`.** Bằng đúng `_SNAPLEN` trong `idps/capture/live.py`. Snaplen khác nhau thì `cap_len` khác
  nhau ngay ở frame đầu tiên dài hơn snaplen nhỏ. Mặc định của `tcpdump` hiện nay là 262144 — lớn hơn
  MTU 1500 nên thực tế không cắt gì, nhưng viết tường minh thì lý lẽ "không frame nào bị cắt" không phụ
  thuộc vào phiên bản tcpdump.
- **`-U` (unbuffered).** Ghi từng packet ra ngay. Không có nó, `docker stop` có thể cắt tiến trình khi
  4 KB cuối còn trong buffer của libpcap → file thiếu packet cuối.
- **Thứ tự bật/tắt: live bật trước, tắt sau.** Cửa sổ của `tcpdump` nằm **trong** cửa sổ của live, và hai
  đầu đều có 4 giây im lặng, nên không frame nào rơi vào khe hở giữa hai lần bật/tắt.
- **`docker stop -t 5`** gửi SIGTERM cho PID 1 của container phụ, tức chính `tcpdump` (lệnh truyền thẳng,
  không qua shell) → nó đóng file rồi thoát.

## 3. Kết quả mong đợi

Điều kiện dừng của T11.1: thư mục có `live.jsonl`, `input.pcap`, `pcap.jsonl`, `run.log`, `README.md`;
lệnh so sánh in **0 khác biệt** ở mọi trường còn lại sau khi bỏ `packet_id`, `timestamp`, `source`.

## 4. Kết quả thực tế

```sh
$ cat TEST/E2E-01_live-vs-pcap/run.log
live processed=42 unknown=0 malformed=0
live exit=0
pcap processed=42 unknown=0 malformed=0
pcap exit=0
diff lines=0
$ wc -c TEST/E2E-01_live-vs-pcap/live.jsonl TEST/E2E-01_live-vs-pcap/pcap.jsonl
35526 live.jsonl
35526 pcap.jsonl
```

`diff lines=0` → **đạt**. Hai tệp còn bằng nhau **từng byte một** về tổng độ dài, và 42 dòng chỉ khác
nhau ở đúng ba trường đã bỏ.

Mạnh hơn điều kiện dừng đòi: nếu **giữ** `packet_id` và chỉ bỏ `timestamp` với `source` thì `diff` vẫn
rỗng — tức hai đường không chỉ ra cùng nội dung mà còn **cùng số lượng và cùng thứ tự** packet:

```sh
$ S2='s/"timestamp":"[^"]*","source":"[a-z]*",/"timestamp":"T","source":"S",/'
$ sed "$S2" live.jsonl > /tmp/l2; sed "$S2" pcap.jsonl > /tmp/p2; diff /tmp/l2 /tmp/p2 | wc -l
0
```

Thống kê 42 event (giống nhau ở cả hai tệp):

| Khoá | Phân bố |
|---|---|
| `status` | 42 × `ok` (0 `unknown`, 0 `malformed`) |
| `transport_proto` | 40 × TCP, 2 × UDP |
| `app_proto` | 4 × HTTP, 7 × SMTP, 2 × DNS, 29 × `null` |
| `detect_method` | 13 × `port+payload`, 29 × `null` |
| `cap_len` vs `wire_len` | bằng nhau ở cả 42 event; dài nhất 305 byte |
| `ipv4.ttl` | 23 × 63 (chiều attacker → victim), 19 × 64 (chiều victim → attacker) |
| `ethernet` | chỉ hai MAC: `6a:91:f8:c9:f4:ba` (int0 của sensor) và `be:68:f8:11:16:f7` (victim) |

29 event có `app_proto` là `null` là các packet **không có payload** (SYN, SYN-ACK, ACK trống, FIN) —
REQ-15.4 nói rõ: không payload thì không có gì để nhận diện, và đó không phải lỗi.

Bảng 42 packet (rút gọn — cột cuối là 34 byte đầu của payload):

| # | flow | ttl | flags | payload | `app_proto` | app |
|---|---|---|---|---|---|---|
| 1–3 | 35944→80 | 63/64 | SYN, SYN-ACK, ACK | 0 | `null` | — |
| 4 | 35944→80 | 63 | PSH,ACK | 74 | HTTP | `GET /` |
| 5 | 80→35944 | 64 | ACK | 0 | `null` | — |
| 6 | 80→35944 | 64 | PSH,ACK | 239 | HTTP | `200 OK` |
| 7–10 | 35944↔80 | | ACK, FIN-ACK ×2, ACK | 0 | `null` | — |
| 11–13 | 35950→80 | | SYN, SYN-ACK, ACK | 0 | `null` | — |
| 14 | 35950→80 | 63 | PSH,ACK | 168 | HTTP | `POST /submit`, `body_len=18` |
| 16 | 80→35950 | 64 | PSH,ACK | 163 | HTTP | `200 OK` |
| 21 | 42003→53 | 63 | — (UDP) | 55 | DNS | `id=22179`, query, `ancount=0` |
| 22 | 53→42003 | 64 | — (UDP) | 59 | DNS | `id=22179`, response, `ancount=1` |
| 26 | 48818→25 | 63 | PSH,ACK | 47 | SMTP | `EHLO`, **`lines` 3 phần tử** |
| 28 | 25→48818 | 64 | PSH,ACK | 34 | SMTP | `220 victim.lab Python SMTP 1.4.6` |
| 30/32/34 | 25→48818 | 64 | PSH,ACK | 16/14/10 | SMTP | `250-victim.lab` · `250-8BITMIME` · `250 HELP` |
| 36 | 25→48818 | 64 | PSH,ACK | 8 | SMTP | `250 OK` (đáp `MAIL FROM`) |
| 38 | 25→48818 | 64 | PSH,ACK | 9 | SMTP | `221 Bye` |
| còn lại | | | ACK / FIN-ACK | 0 | `null` | — |

## 5. Vì sao bắt PCAP trong netns của sensor, không phải trong attacker

`tasks.md` viết T11.1 là "cùng lúc chạy `idps` bắt trên `int0` và `tcpdump` trong `attacker`". **Làm đúng
như vậy thì điều kiện dừng không bao giờ đạt được**, và không phải vì code sai.

`attacker:eth0` nằm trên `net_ext`, `sensor:int0` nằm trên `net_int` — **hai đoạn mạng lớp 2 khác nhau**,
cách nhau một bước định tuyến. Router (kernel của sensor) làm đúng hai việc RFC 1812 §5.3.1 đòi: **viết
lại header Ethernet** và **giảm TTL**. Đo trực tiếp trên cùng một loại SYN của cùng một lệnh `curl`:

```sh
# nhìn từ attacker:eth0
$ docker compose exec -T attacker tcpdump -i eth0 -n -v -e -c 1 'tcp dst port 80 and tcp[tcpflags] & tcp-syn != 0'
16:ca:66:16:0b:14 > 4e:6b:2c:dd:fd:bc, ethertype IPv4 (0x0800), length 74:
    IP (tos 0x0, ttl 64, ...) 10.10.0.10.47078 > 10.20.0.10.80: Flags [S]

# nhìn từ sensor:int0 (cùng netns với sensor)
$ docker run --rm --network "container:$(docker compose ps -q idps)" ... idps-attacker \
      tcpdump -i int0 -p -n -e -c 1 'tcp dst port 80 and tcp[tcpflags] & tcp-syn != 0'
6a:91:f8:c9:f4:ba > be:68:f8:11:16:f7, ethertype IPv4 (0x0800), length 74:
    10.10.0.10.39556 > 10.20.0.10.80: Flags [S]
```

Cùng một packet IP, nhưng ở hai chỗ đo có **ba trường khác nhau** trong event: `ethernet.src_mac`,
`ethernet.dst_mac` và `ipv4.ttl` (64 ở attacker, 63 ở int0). Ba trường đó khác ở **cả 42 event**, nên
`diff` sẽ in 42 khối chênh lệch — và cả 42 khối đó đều **không nói gì** về việc live và PCAP có cho cùng
kết quả hay không.

Sâu hơn: REQ-3.2 đòi so sánh khi "**cùng một chuỗi packet** được đưa vào qua live capture và qua PCAP".
PCAP bắt ở attacker **không phải cùng một chuỗi packet** — nó là cùng một phiên nhìn từ một điểm khác.
Muốn "cùng một chuỗi packet" theo nghĩa chặt thì hai máy nghe phải cắm vào **cùng một interface**, và
trong Docker cách làm điều đó mà không sửa image của sensor là cho container phụ **dùng chung network
namespace**: `--network "container:<id của sensor>"`. Container phụ dùng image `idps-attacker` (đã có
`tcpdump`), giữ nguyên `cap_drop: ALL` + `NET_RAW` + `SETUID`/`SETGID` như service `attacker` trong
`compose.yaml` — `SETUID`/`SETGID` là để `tcpdump` của Debian tự hạ quyền xuống user `tcpdump`.

Vì sao **không** cài `tcpdump` vào image của sensor: image đó là phần mềm chạy thật, mỗi gói thêm vào là
một bề mặt tấn công thêm (§8.3). Một công cụ chỉ dùng để đo thì đặt trong container dùng một lần rồi bỏ.

Thay đổi này đã ghi lại ở đây thay vì sửa lặng lẽ, vì khi vấn đáp phải bảo vệ được **cả hai**: vì sao
kế hoạch ban đầu không đo được điều nó muốn đo, và vì sao cách thay thế đo đúng.

## 6. Ba trường bị loại khỏi phép so sánh

`STRIP` cắt đúng phần đầu cố định của mỗi dòng. Được phép cắt bằng `sed` vì NFR-2 bảo đảm **thứ tự khoá
trong JSON là cố định** (`new_event()` dựng đủ khoá theo thứ tự §5.4, `dict` của Python giữ thứ tự chèn),
nên `packet_id`, `timestamp`, `source` luôn là khoá số 2, 3, 4 — không cần công cụ đọc JSON nào.
`schema_version` **không** bị cắt: nó phải giống nhau, và nó giống nhau.

| Trường | Vì sao phải bỏ |
|---|---|
| `source` | Bằng định nghĩa: `"live"` vs `"pcap"`. Trường này tồn tại chính là để module bài sau biết event đến từ đâu; nó khác nhau là **mục đích**, không phải lỗi |
| `packet_id` | Là số đếm từ 1 **trong một lần chạy**. Sensor live có thể đã chạy từ trước và đếm tiếp; chỉ ở test này hai con số mới trùng nhau vì hai tap thấy đúng cùng tập frame (§4) |
| `timestamp` | Hai đường lấy nhãn thời gian bằng hai cơ chế khác nhau — xem dưới |

Đo chênh lệch `timestamp` của từng cặp event (đơn vị micro giây, live − pcap):

| Chênh lệch | Số event |
|---|---|
| 0 | 31 |
| ±1 | 6 |
| −11, −31, −34, −38, −38 | 5 |

**37/42 event lệch không quá 1 µs** — đúng giới hạn mà docstring của `LiveSource.frames()` đã nêu trước
khi đo: Scapy trả nhãn thời gian dạng `float` (`tv_sec + tv_nsec * 1e-9`), mà ở mốc thời gian hiện nay
(≈1.77×10⁹ giây) một `double` chỉ còn phân giải cỡ 0,4 µs, rồi `int(ts * 1_000_000)` cắt xuống. Bản PCAP
thì đi qua số nguyên micro giây của libpcap. Hai đường làm tròn khác nhau → lệch 0 hoặc 1 µs.

**5 event lệch 11–38 µs thì float không giải thích được**, và đây là chỗ phải nói thẳng giới hạn của
phép đo: hai tap đọc nhãn thời gian qua hai đường khác nhau của kernel — Scapy qua dữ liệu phụ trợ
`SO_TIMESTAMPNS` của `recvmsg` (đã kiểm: `getsockopt(SOL_SOCKET, SO_TIMESTAMPNS)` trên socket của
`LiveSource` trả về `1`, nên **không** phải trường hợp Scapy rơi về `time.time()`), libpcap qua trường
`tp_sec`/`tp_nsec` của vòng đệm `TPACKET`. Kernel chỉ đóng dấu thời gian cho một frame **khi có tap cần
tới** (`net_timestamp_check`), nên hai tap chạy ở hai thời điểm khác nhau có thể ghi hai giá trị khác
nhau cho cùng một frame. Đó là giả thuyết khớp với số đo (chênh lệch nhỏ, không đều, cả hai dấu), nhưng
**chưa chứng minh được** trong phạm vi bài này.

Kết luận về `timestamp` không đổi dù nguyên nhân là cái nào: **REQ-3.2 nói về kết quả bóc tách, không nói
về đồng hồ.** Một IDS có thể đòi hai bản ghi của cùng một packet phải có cùng `src_ip`, cùng `payload`,
cùng `app_proto` — nhưng không thể đòi hai máy nghe độc lập đọc đồng hồ ra cùng một chữ số micro giây.

## 7. R1 (design §11) đã không xảy ra

R1 ghi: *"`bytes(pkt)` của packet Scapy sniff được **dựng lại** từ trường thay vì trả bytes gốc (khác
bytes trên dây với packet lỗi)"*, và cách đo được chỉ định sẵn là "test E2E live vs PCAP so sánh
`payload_b64`".

Kết quả: **cả 42 cặp `payload_b64` giống nhau**, tổng cộng 1216 ký tự base64. Không chỉ payload — toàn bộ
`ethernet`, `ipv4`, `tcp`, `udp`, `app` của 42 event khớp từng byte, tức mọi trường được dựng **từ** bytes
đó cũng khớp. Nguyên nhân: `LiveSource` dùng `sock.recv_raw()` chứ không `sniff()` + `bytes(pkt)` — đúng
phương án ADR-2 đã chốt, và R1 đã ghi sẵn `recv_raw` là phương án phòng khi rủi ro xảy ra.

Hai giới hạn của bằng chứng này, phải tự nói ra trước khi bị hỏi:

1. **42 packet này đều hợp lệ.** R1 nói về packet *lỗi* ("khác bytes trên dây với packet lỗi"). Packet
   hỏng chỉ được đưa vào bằng đường PCAP (TC-12), vì kernel của lab không chịu phát ra một header IPv4
   có `total_length` sai — muốn có thì phải tự ghép frame bằng raw socket, ngoài phạm vi bài 1.
2. **Lab không có VLAN.** `recv_raw()` có đúng một chỗ Scapy *chèn* byte: khi frame mang VLAN tag, kernel
   tách tag ra khỏi dữ liệu và Scapy đặt 4 byte tag trở lại offset 12 dựa vào `PACKET_AUXDATA`. Đó là
   *khôi phục* bytes trên dây, không phải *dựng lại* packet, nhưng nhánh đó không được test case này chạy
   qua.

## 8. Nhận xét

- **Live bắt được một ca mà TC-09 nói là không bắt được bằng `nc`.** Packet 26 mang **cả ba lệnh trong
  một segment** (`EHLO e2e.lab\r\nMAIL FROM:<probe@e2e.lab>\r\nQUIT\r\n`, 47 byte) → event có
  `command="EHLO"`, `argument="e2e.lab"` và `lines` **3 phần tử**. `TC-09/README.md` §7 viết ca
  pipelining (RFC 2920) "không bắt được bằng `nc` gõ tay" — đúng với **cách gõ của TC-09**: ở đó mỗi lệnh
  là một `printf` riêng cách nhau `sleep 1`, nên mỗi lệnh thành một segment. Ở đây một `printf` viết cả
  ba lệnh vào ống, `nc` gọi `write()` một lần và gửi ngay **trước khi banner `220` của server tới**, nên
  ba lệnh nằm trong một segment. Bài học cho việc dựng test: **ranh giới segment do bên gửi quyết định,
  và `sleep` giữa hai lần ghi chính là thứ quyết định** (cùng bài học của TC-10 nhìn từ chiều server).
- **TTL 63/64 là bằng chứng gói thật sự đi xuyên sensor** (REQ-19.5): 23 packet chiều attacker → victim
  có `ttl=63` vì kernel của sensor đã giảm 1; 19 packet chiều ngược lại có `ttl=64` vì trên `int0` chúng
  **chưa** được định tuyến. Nếu sensor chỉ là một máy cắm cùng bridge (không phải router) thì cả 42
  packet đều `ttl=64`.
- **Không có frame ARP nào trong cửa sổ đo** — cache ARP của sensor và victim đã nóng từ các lệnh trước.
  Nếu cache hết hạn giữa lúc đo thì phép so sánh vẫn đứng, vì hai tap ở **cùng một interface** nên cùng
  thấy các frame ARP đó; chúng chỉ thêm vào cả hai tệp các event `network_proto="UNKNOWN"` (hình dạng đã
  có bằng chứng riêng ở TC-11).
- **`processed=42` khớp với `42 packets captured` của tcpdump và `0 packets dropped by kernel`.** Với
  traffic thưa như lab thì không có packet nào bị kernel bỏ; ở tốc độ cao thì hai con số này sẽ lệch, và
  đó là giới hạn đã ghi ở design §10 (xử lý đồng bộ, không hàng đợi).
- **Đây cũng là bằng chứng duy nhất của repo cho REQ-18.4 và cho đường dừng bằng SIGTERM.** `live exit=0`
  nghĩa là `main.py` nhận SIGTERM, ném `KeyboardInterrupt`, Runner đóng sink trong `finally`, thống kê in
  ra **sau** khi file đã đóng — nên `processed=42` trong `run.log` và 42 dòng trong `live.jsonl` không thể
  lệch nhau (REQ-13.5, REQ-20.3).
