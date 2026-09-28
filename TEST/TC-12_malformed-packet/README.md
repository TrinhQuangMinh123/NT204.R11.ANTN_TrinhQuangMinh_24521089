# TC-12 — Malformed packet

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-15.1–15.3 (packet hỏng → ghi lỗi, không dừng chương trình), REQ-2.5 (bản ghi PCAP bị cắt), REQ-4.3, REQ-5.5, REQ-6.2, REQ-8.4, REQ-8.5, REQ-7.5, **NFR-1** (0 lỗi `internal`) |
| Task | T10.3 · Phase 10 |
| Ngày ghi | 2026-09-28 |
| Traffic | PCAP **dựng bằng script** `tests/tools/make_bad_pcaps.py` (ADR-11) |
| Kết quả | 10 bản ghi, `processed=10 unknown=0 malformed=10`, **exit 0**, **0** lỗi `internal` |
| `md5sum input.pcap` | `0ec8ea921fd1dbbe544da1e9fff55e72` |
| `sha256` do script in ra | `5e711ae30ae25d8bbc18e9fa5197e62d416ee541e489a1852d2c953822c30139` |

## 1. Kịch bản

Mười bản ghi, **mỗi bản ghi hỏng đúng một chỗ** và tầng dưới chỗ hỏng luôn hợp lệ. Nhờ tính chất đó,
`errors[].layer` trong output chỉ ra được **chính xác** parser nào bắt được lỗi — nếu một packet cho ra
lỗi ở tầng khác dự kiến thì đó là bug thật, không phải do payload dựng nhập nhèm.

| # | Chỗ hỏng | Tầng dự kiến báo | Yêu cầu |
|---|---|---|---|
| 1 | Chỉ có 12 byte cho header IPv4 (cần 20) | `ipv4` | REQ-4.3 |
| 2 | `IHL = 3` → khai header 12 byte | `ipv4` | REQ-4.3 |
| 3 | `total_length = 200` nhưng chỉ có 40 byte | `ipv4` | REQ-4.3 |
| 4 | TCP `data_offset = 2` → khai header 8 byte | `tcp` | REQ-5.5 |
| 5 | TCP `data_offset = 15` (60 byte) trên segment 20 byte | `tcp` | REQ-5.5 |
| 6 | UDP `length = 100` nhưng datagram 13 byte | `udp` | REQ-6.2 |
| 7 | DNS: con trỏ nén **tự trỏ vào chính nó** | `dns` | REQ-8.4 |
| 8 | DNS: `ANCOUNT = 5` nhưng chỉ có 1 answer | `dns` | REQ-8.5 |
| 9 | HTTP: byte `0xFF` trong một dòng header | `http` | REQ-7.5 |
| 10 | Bản ghi PCAP **cuối bị cắt 6 byte** | `capture` | REQ-2.5 |

**Vì sao phải dựng bằng script (ADR-11):** không hệ điều hành nào chịu tạo ra các packet này. Kernel
Linux tự tính `total_length` và `IHL`, `nc` tự tính `length` của UDP, và không có cờ nào bảo `dnsmasq`
trả một con trỏ nén tự trỏ vào nó. Đây đúng là loại dữ liệu **chỉ kẻ tấn công hoặc một script** tạo ra
— nên cách kiểm chứng trung thực nhất là tự ghép từng byte (chi tiết trong `make_bad_pcaps.py`).

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-12_malformed-packet
python tests/tools/make_bad_pcaps.py     # sinh input.pcap (sha256 in ra để đối chiếu)

docker compose run --rm idps-offline python main.py \
    --pcap $TC/input.pcap -o $TC/output.jsonl > /tmp/raw.log 2>&1
code=$?
grep -v '^ *Container ' /tmp/raw.log > $TC/run.log
echo "exit=$code" >> $TC/run.log
```

Mã thoát phải lấy **trước** khi đi qua pipe: `$?` sau `| grep` là mã của `grep`, không phải của
`main.py` — mà exit 0 chính là một phần của điều kiện dừng (NFR-1).

## 3. Kết quả mong đợi

Điều kiện dừng của T10.3: đủ 4 tệp; `run.log` exit 0; **số dòng output = số bản ghi**;
`grep -c '"layer":"internal"'` → `0`; mỗi packet có `errors[].layer` đúng tầng ở bảng §1; bản ghi cuối
bị cắt có lỗi `"layer":"capture"`.

## 4. Kết quả thực tế

```sh
$ cat TEST/TC-12_malformed-packet/run.log
processed=10 unknown=0 malformed=10
exit=0
$ wc -l < TEST/TC-12_malformed-packet/output.jsonl
10
$ grep -c '"layer":"internal"' TEST/TC-12_malformed-packet/output.jsonl
0
$ grep -o '"layer":"[a-z0-9]*"' TEST/TC-12_malformed-packet/output.jsonl
"layer":"ipv4"
"layer":"ipv4"
"layer":"ipv4"
"layer":"tcp"
"layer":"tcp"
"layer":"udp"
"layer":"dns"
"layer":"dns"
"layer":"http"
"layer":"capture"
"layer":"ipv4"
```

10 bản ghi → 10 dòng, exit 0, **0** lỗi `internal`, và thứ tự các `layer` khớp từng dòng với bảng §1
(dòng cuối có **hai** lỗi — xem §6) → **đạt**.

Lưu ý lớp ký tự trong lệnh grep: phải là `[a-z0-9]`, không phải `[a-z]`. Tên tầng `ipv4` **có chữ số**,
nên `[a-z]*` bỏ sót đúng ba dòng đầu và làm người đọc tưởng chúng không có lỗi nào. Đây là loại sai sót
phải tự kiểm bằng cách đối chiếu **số dòng grep ra** với **số bản ghi đã biết** (11 dòng lỗi / 10 bản
ghi, vì bản ghi cuối có hai lỗi).

## 5. Từng packet: parser nào bắt được, nhờ dòng kiểm tra biên nào

Đây là nội dung của V10.4. Thông điệp lỗi lấy nguyên từ `output.jsonl`.

| # | `errors[0].reason` | Bắt bởi |
|---|---|---|
| 1 | `ipv4 header needs 20 bytes, got 12` | `need(data, 0, IPV4_MIN_HEADER_LEN)` — kiểm **trước** khi `unpack_from`, nên `struct.error` không bao giờ được ném (`ipv4.py:66`) |
| 2 | `ipv4 ihl=3 is below minimum 5 (header would be 12 bytes)` | so `ihl` với `IPV4_MIN_IHL` (`ipv4.py:111`). Không kiểm thì `payload = data[ihl*4:]` sẽ lấy **12 byte cuối của header** làm payload TCP |
| 3 | `ipv4 total_length=200 exceeds available 40 bytes` | so `total_length` với `len(data)` (`ipv4.py:136`). Không kiểm thì payload bị cắt ngắn *im lặng* và mọi con số tầng trên sai theo |
| 4 | `tcp data_offset=2 is below minimum 5 (header would be 8 bytes)` | so với `TCP_MIN_HEADER_LEN` (`tcp.py:94`) |
| 5 | `tcp header declares 60 bytes (data_offset=15), got 20` | so `header_len` với số byte thật có (`tcp.py:103`) |
| 6 | `udp length=100 does not match available 13 bytes` | so `length` với `len(data)` (`udp.py:60`). UDP là tầng **duy nhất** đòi khớp **đúng** (`!=`), không phải "không vượt quá": header UDP nói trọn độ dài datagram, lệch một byte là dữ liệu sai |
| 7 | `dns answer 1/1: dns name starting at offset 28 has a compression pointer loop back to offset 28` | tập `seen` các offset đã đọc trong `_read_name` (`dns.py:152`) — chặn ngay **lần lặp đầu**, không phải sau N lần nhảy (I-6) |
| 8 | `dns answer 2/5: dns name starting at offset 44 runs past the end of the payload at offset 44` | `need()` trong `_read_name` (`dns.py:145`): `ANCOUNT` khai 5 nên vòng lặp đọc tới answer thứ 2, nhưng payload đã hết |
| 9 | `http header line 3 cannot decode as ascii: byte 0xff at offset 8` | `raw.decode("ascii")` **nghiêm ngặt** trong `_parse_headers` (REQ-7.5). `errors="replace"` sẽ đổi `0xFF` thành `U+FFFD` và **không có lỗi nào để ghi** |
| 10 | `truncated record` + `ipv4 total_length=58 exceeds available 52 bytes` | `RawFrame.truncated` do `PcapSource` đặt (`incl_len` khai 66, file chỉ còn 60) → pipeline ghi lỗi `capture` rồi **vẫn parse tiếp** (REQ-2.5) |

Điểm chung của 9 dòng đầu: **mọi lỗi đều được phát hiện bằng một phép so sánh số, TRƯỚC khi đọc byte**,
không phải bằng `try/except` quanh `struct.unpack`. Đó là lý do NFR-1 đo được bằng "0 lỗi `internal`":
lỗi `internal` chỉ xuất hiện khi một parser **thiếu** một phép so sánh như thế (xem `pipeline.py`, lưới
`except Exception`).

## 6. Packet 10: một nguyên nhân, hai tầng cùng báo

```
errors: [{"layer":"capture","reason":"truncated record"},
         {"layer":"ipv4","reason":"ipv4 total_length=58 exceeds available 52 bytes"}]
```

Cả hai đều đúng và **không** dư:

- `capture` nói về **vỏ file**: bản ghi khai `incl_len` byte nhưng file hết sớm hơn (tcpdump bị kill
  giữa lúc ghi, đĩa hết chỗ, hoặc file bị cắt khi copy).
- `ipv4` nói về **nội dung còn lại**: sau khi mất 6 byte cuối, header IPv4 khai `total_length = 58`
  trong khi chỉ còn 52 byte. Parser IPv4 không biết gì về vỏ file — nó chỉ thấy các con số không khớp.

Đây là lý do `errors` là một **list** chứ không phải một trường đơn (`event.py::add_error`): một packet
có thể hỏng ở nhiều tầng, và gộp chúng thành một chuỗi sẽ làm mất thông tin "tầng nào phát hiện".

Cũng lưu ý pipeline **không dừng** ở lỗi `capture`: nó ghi lỗi rồi parse tiếp phần đọc được (REQ-2.5).
Phần đầu frame thường còn nguyên, và với một IDS thì `src_ip`/`dst_ip` của một packet bị cắt vẫn là
thông tin dùng được — ném đi là mất bằng chứng không cần thiết.

## 7. REQ-14.1/15.2: giữ lại mọi thứ đã parse được trước chỗ hỏng

Lỗi là chỗ **dừng**, không phải chỗ **xoá**. Lấy nguyên từ `output.jsonl`:

| # | Vẫn còn trong event | Ý nghĩa với một IDS |
|---|---|---|
| 2 | `ipv4.ihl = 3`, `total_length = 40`, `src_ip = 10.10.0.10` | **con số SAI được giữ nguyên** — chính nó là bằng chứng; `ihl=3` không xuất hiện ngoài ý muốn bao giờ |
| 4, 5 | `src_port = 40470`, `dst_port = 80`, `tcp.flags = ["PSH","ACK"]`, `data_offset` sai | vẫn viết được luật theo 5-tuple, dù header TCP không đọc tiếp được |
| 7 | `app.questions = [{"name":"victim.lab","type":"A"}]`, `answers = []` | question parse xong **trước** khi gặp con trỏ vòng lặp trong answer → tên miền bị hỏi vẫn còn |
| 8 | `answers` giữ **1** answer (`victim.lab`/A/300/`10.20.0.10`) dù `ancount = 5` | đúng REQ-8.5: giữ bản ghi đã đọc được, `ancount` giữ **con số bên gửi KHAI** để hai số lệch nhau nhìn thấy được |
| 9 | `app.method = "GET"`, `uri = "/"`, `version`, `headers = [["Host","10.20.0.10"]]` | dòng header thứ 3 hỏng, **hai** dòng trước vẫn còn; parser dừng đúng chỗ thay vì đoán tiếp |

Packet 7 và 8 còn chứng minh một điều nữa: **chúng được nhận diện là DNS** (`app_proto: "DNS"`) rồi mới
báo lỗi. Đó là vì con trỏ xấu và `ANCOUNT` sai nằm trong phần **answer**, còn phần **question** vẫn
parse trọn — mà chữ ký Phụ lục C của DNS chính là "parse được trọn phần question". Nếu đặt chỗ hỏng vào
question thì chữ ký không khớp và event sẽ ra `app_proto: "UNKNOWN"`, `status: "ok"` — **không** phải
`malformed` (ranh giới đã chốt ở V8.1, design ADR-5). Script dựng PCAP cố tình đặt đúng chỗ, và
`make_bad_pcaps.py::dns_pointer_loop` ghi lý do ngay tại hàm.

## 8. Nhận xét

- **`unknown=0` mà `malformed=10`.** Hai con số này đo hai việc khác nhau và không chồng nhau ở đây:
  `unknown` = "chương trình chưa hỗ trợ loại này" (TC-11), `malformed` = "byte không khớp với chính
  header của nó" (TC-12). Đúng thứ tự ưu tiên của design §5.4: `malformed` > `unknown` > `ok`.
- **`app_proto` là `null` ở 7 trong 10 packet.** Lỗi ở tầng transport trở xuống thì pipeline dừng trước
  khi tới detector — không có payload nào để nhận diện. Chỉ packet 7, 8 (DNS) và 9 (HTTP) đi được tới
  tầng ứng dụng, vì ở chúng mọi tầng dưới đều hợp lệ.
- **Không packet nào làm chương trình dừng, và không packet nào bị bỏ qua.** 10 bản ghi vào → 10 dòng
  JSON ra → exit 0. Đây là NFR-1, và nó là tính chất quan trọng nhất của một IDS đặt trước mặt
  attacker: một packet 40 byte dựng tay không được phép làm cả sensor mù.
- **`0` lỗi `internal` là một phép đo, không phải một lời hứa.** Lưới `except Exception` trong
  `pipeline.py` luôn ở đó; con số 0 nghĩa là trên bộ packet này **chưa** có đường nào chạm tới nó. Thêm
  packet hỏng kiểu mới vào `make_bad_pcaps.py` rồi chạy lại là cách rẻ nhất để tìm chỗ thiếu kiểm tra
  biên tiếp theo.
