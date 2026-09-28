# TC-11 — Unknown protocol

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-17.2 (linktype/giao thức chưa hỗ trợ → `UNKNOWN`, không phải lỗi), REQ-17.3 (tầng dưới đã parse vẫn giữ nguyên), REQ-14.1, REQ-14.3 |
| Task | T10.2 · Phase 10 |
| Ngày ghi | 2026-09-28 |
| Traffic | PCAP **dựng bằng script** `tests/tools/make_bad_pcaps.py` (ADR-11) |
| Kết quả | `input.pcap`: 5 packet, `processed=5 unknown=4 malformed=0`, exit 0 · `input-linktype.pcap`: 1 packet, `processed=1 unknown=1 malformed=0`, exit 0 |
| `md5sum input.pcap` | `74c66155f2132d061ea73b7a4eee19a0` |
| `md5sum input-linktype.pcap` | `b4f49bf4d478105bf6be7d599b9cb91d` |
| `sha256` của script sinh ra | `f0353435…8bf2` (input.pcap) · `09e29902…062d` (input-linktype.pcap) |

## 1. Kịch bản

Bốn tầng của pipeline (Link → Network → Transport → App), và **bốn packet dừng ở bốn tầng khác nhau**
— cộng một file riêng cho tầng liên kết:

| # | Packet | Tầng nói `UNKNOWN` | Vì sao |
|---|---|---|---|
| 1 | ARP request | `network_proto` | EtherType `0x0806`, không phải `0x0800` |
| 2 | IPv6 header | `network_proto` | EtherType `0x86DD` |
| 3 | ICMP echo request | `transport_proto` | IPv4 hợp lệ, `protocol = 1` không có trong `TRANSPORT_PARSERS` |
| 4 | IPv4 protocol 47 (GRE) | `transport_proto` | cùng lý do, nhưng là giao thức "không quen" |
| 5 | TCP :22 mang banner SSH | `app_proto` | ba tầng dưới hợp lệ, không chữ ký ứng dụng nào khớp |
| (file 2) | frame LINUX_SLL | `link_proto` | linktype `113`, bài 1 chỉ hỗ trợ `1` (Ethernet) |

**Vì sao PCAP dựng chứ không bắt thật (ADR-11).** Vài packet ở đây *bắt được* trong lab (ARP do bridge
Docker sinh ra, ICMP do `ping`), nhưng một file chứa **đúng một packet cho mỗi ca, theo thứ tự cố định,
không lẫn packet nào khác** thì chỉ script tạo ra được. GRE và SSH :22 thì lab không có dịch vụ nào
sinh ra. Và điều test case này muốn chứng minh là **cái bảng bên trên** — tầng nào nói `UNKNOWN` — nên
mỗi dòng phải là một packet sạch, không nhiễu.

## 2. Lệnh tái hiện

```sh
TC=TEST/TC-11_unknown-protocol
python tests/tools/make_bad_pcaps.py     # sinh cả input.pcap và input-linktype.pcap

: > $TC/run.log
for f in input:output input-linktype:output-linktype; do
    src=${f%%:*}; dst=${f##*:}
    docker compose run --rm idps-offline python main.py \
        --pcap $TC/$src.pcap -o $TC/$dst.jsonl > /tmp/raw.log 2>&1
    code=$?
    grep -v '^ *Container ' /tmp/raw.log >> $TC/run.log
    echo "exit=$code" >> $TC/run.log
done
```

Hai chi tiết khác các TC trước:

- **`run.log` có thêm dòng `exit=…`** vì điều kiện dừng của T10.2/T10.3 đòi chứng minh **exit 0**:
  một bộ packet lạ/hỏng không được làm chương trình chết (NFR-1). Mã thoát phải lấy **trước** khi đi
  qua pipe (`| grep`), vì `$?` sau pipe là mã của `grep` chứ không phải của `main.py`.
- **Không `-c N`, không `tcpdump`** — file do script sinh, `sha256sum` là bằng chứng lặp lại được
  (`python tests/tools/make_bad_pcaps.py --check` in ra mà không ghi file).

## 3. Kết quả mong đợi

Điều kiện dừng của T10.2: đủ tệp (có cả `input-linktype.pcap` và `output-linktype.jsonl`); `run.log`
exit 0; **số dòng output = số packet**; ARP/IPv6 → `"network_proto":"UNKNOWN"`; ICMP/GRE →
`"transport_proto":"UNKNOWN"`; SSH :22 → `"app_proto":"UNKNOWN"`; linktype khác → `"link_proto":"UNKNOWN"`.

## 4. Kết quả thực tế

```sh
$ cat TEST/TC-11_unknown-protocol/run.log
processed=5 unknown=4 malformed=0
exit=0
processed=1 unknown=1 malformed=0
exit=0
$ wc -l < TEST/TC-11_unknown-protocol/output.jsonl
5
$ wc -l < TEST/TC-11_unknown-protocol/output-linktype.jsonl
1
$ grep -c '"network_proto":"UNKNOWN"' TEST/TC-11_unknown-protocol/output.jsonl
2
$ grep -c '"transport_proto":"UNKNOWN"' TEST/TC-11_unknown-protocol/output.jsonl
2
$ grep -c '"app_proto":"UNKNOWN"' TEST/TC-11_unknown-protocol/output.jsonl
1
$ grep -o '"link_proto":"[^"]*"' TEST/TC-11_unknown-protocol/output-linktype.jsonl
"link_proto":"UNKNOWN"
```

5 packet → 5 dòng, 1 packet → 1 dòng, exit 0 cả hai, bốn tầng đều có ca `UNKNOWN` → **đạt**.

Toàn bộ sáu event (`errors` = `[]` ở cả sáu):

| # | `link_proto` | `network_proto` | `transport_proto` | `app_proto` | `status` |
|---|---|---|---|---|---|
| 1 ARP | Ethernet | **UNKNOWN** | `null` | `null` | unknown |
| 2 IPv6 | Ethernet | **UNKNOWN** | `null` | `null` | unknown |
| 3 ICMP | Ethernet | IPv4 | **UNKNOWN** | `null` | unknown |
| 4 GRE | Ethernet | IPv4 | **UNKNOWN** | `null` | unknown |
| 5 SSH :22 | Ethernet | IPv4 | TCP | **UNKNOWN** | **ok** |
| file 2 | **UNKNOWN** | `null` | `null` | `null` | unknown |

## 5. `unknown=4` chứ không phải 5 — và đó là điểm dễ bị hỏi nhất

`input.pcap` có **năm** packet mang `UNKNOWN` ở đâu đó, nhưng thống kê chỉ đếm **bốn**. Không phải lỗi
đếm: `unknown=` đếm số event có `status == "unknown"`, và `status` chỉ thành `"unknown"` khi
`link_proto`, `network_proto` **hoặc** `transport_proto` là `UNKNOWN` (design §5.4). `app_proto` cố
tình **không** nằm trong danh sách đó (`_UNKNOWN_KEYS` của `event.py`).

Lý do là một phân biệt về ngữ nghĩa, không phải một quy ước tuỳ ý:

- `transport_proto = "UNKNOWN"` nghĩa là **chương trình dừng lại**: nó không đọc được gì thêm, mọi
  trường phía trên đều `null`. Event đó *thiếu dữ liệu*.
- `app_proto = "UNKNOWN"` nghĩa là **chương trình đã đọc xong mọi thứ nó hứa đọc**: 5-tuple đủ, cờ TCP
  đủ, payload nằm nguyên trong `payload_b64`. Không có gì thiếu — chỉ là bài 1 mới có ba chữ ký ứng
  dụng. Một luật phát hiện theo port/cờ TCP vẫn chạy được trên event này.

Vì vậy packet 5 (SSH) có `status: "ok"`. Nếu đánh dấu nó `unknown` thì con số `unknown=` trong log sẽ
lẫn hai việc khác nhau, và trên traffic thật (nơi phần lớn payload TCP không phải HTTP/SMTP) nó sẽ lớn
đến mức vô nghĩa.

## 6. REQ-17.3: tầng dưới vẫn giữ nguyên

`UNKNOWN` là chỗ **dừng**, không phải chỗ **xoá**. Ba event dưới đây lấy nguyên từ `output.jsonl`:

```
packet 1 (ARP)   ethernet: {"src_mac":"02:42:0a:0a:00:0a","dst_mac":"02:42:0a:0a:00:fe","ethertype":2054}
                 ipv4: null   tcp: null   udp: null   app: null
packet 3 (ICMP)  ethernet: {…,"ethertype":2048}
                 src_ip: "10.10.0.10"   dst_ip: "10.20.0.10"   ipv4: {version:4, ihl:5, ttl:64, protocol:1, …}
                 tcp: null   udp: null   src_port: null   dst_port: null
packet 5 (SSH)   src_port: 40470   dst_port: 22   tcp: {…, "payload_len":32, "payload_b64":"U1NILTIu…"}
                 app_proto: "UNKNOWN"   detect_method: null   app: null
```

- Packet 1 vẫn cho biết **hai địa chỉ MAC** — đủ để một luật phát hiện ARP spoofing của bài sau chạy,
  dù bài 1 chưa parse ARP.
- Packet 3 vẫn cho biết **IP nguồn/đích và TTL** — đủ để phát hiện ping sweep.
- Packet 5 vẫn giữ **trọn 32 byte payload** trong `payload_b64`: chữ ký `SSH-2.0-…` đọc lại được mà
  không cần sửa parser.
- `ethertype` ghi là **số** (2054 = 0x0806) chứ không phải tên, khác `link_proto` là tên. Đó là quy ước
  của design §5.4: trường nào **có trong header** thì ghi đúng con số trên dây; trường nào là **kết luận
  của chương trình** thì ghi tên.

## 7. Vì sao linktype phải nằm ở một file PCAP riêng

Linktype được khai **một lần duy nhất trong global header** của file PCAP (byte 20–23), không phải trong
từng bản ghi. Một file PCAP cổ điển vì thế chỉ chứa được **một** linktype — muốn có ca "linktype khác
Ethernet" thì buộc phải có file thứ hai. (Định dạng PCAPNG mới cho phép nhiều interface với nhiều
linktype trong một file; bài 1 chỉ hỗ trợ PCAP cổ điển — Phụ lục D, và `main.py` từ chối PCAPNG ngay ở
CLI.)

Nội dung file 2 là một frame **LINUX_SLL** (linktype 113) — đúng thứ `tcpdump -i any` sinh ra, nên đây
là ca sẽ gặp thật nếu chạy sensor sai cờ. Bên trong nó bọc một IPv4 + TCP + `GET / HTTP/1.1` hoàn toàn
hợp lệ, và chương trình **vẫn** trả về `link_proto: "UNKNOWN"` với `errors: []`:

```
{"linktype":113, "link_proto":"UNKNOWN", "network_proto":null, …, "status":"unknown", "errors":[]}
```

Đây là điểm mấu chốt của REQ-17.2 và là chỗ `parse_link()` trả `None` **khác** trả
`ParseResult(error=…)`: "chương trình chưa biết đọc loại này" không phải "byte trong frame sai". Nếu ghi
thành `malformed` thì người đọc log sẽ đi tìm kẻ tấn công, trong khi việc cần làm chỉ là đổi cờ của
tcpdump hoặc thêm một dòng vào `LINK_PARSERS`.

## 8. Nhận xét

- **`detect_method` là `null` ở cả sáu event.** Packet 1–4 chưa tới được tầng ứng dụng; packet 5 thì
  `UNKNOWN` là kết quả của việc **thử hết mà trượt**, không phải một *cách* nhận diện — nên
  `Detection("UNKNOWN", None)` cố tình để `method` rỗng (xem `detector.py`).
- **`app_proto` là `null` (không phải `"UNKNOWN"`) ở packet 1–4.** Ba lý do khác nhau cùng cho `null`:
  packet 1–2 không có tầng transport nên không có payload nào để xét; packet 3–4 có IPv4 nhưng transport
  không đọc được. Còn `"UNKNOWN"` chỉ dùng khi **có payload thật** mà không chữ ký nào khớp (REQ-15.4).
- **Bốn packet đầu không có `errors` nào.** Đó là toàn bộ ý của REQ-17.2: bộ packet này là **traffic
  bình thường** của một mạng thật (ARP và ICMP có mặt trên mọi LAN), chỉ là ngoài phạm vi bài 1.
  TC-12 mới là nơi `errors` phải xuất hiện.
