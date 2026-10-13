# T12 — Idle timeout

| Mục | Giá trị |
|---|---|
| Yêu cầu kiểm chứng | REQ-33.1/33.4 (hết hạn theo ngưỡng của trạng thái), REQ-33.6 + REQ-30.6 (packet sau timeout mở flow **mới**), REQ-36.4/36.5 (log in cấu hình đã dùng), A9 (ngưỡng hạ được để test), Phụ lục K T12 |
| Task | T7.2 · Phase 7 (bài 2) |
| Ngày ghi | 2026-10-13 |
| Input | PCAP **dựng tay**: hai SYN cùng 5-tuple, cách nhau 3 s (`tests/tools/make_timeout_pcap.py`) |
| Kết quả | 2 packet, `processed=2`, **2** flow (`idle_new` + `end_of_run`), exit 0 |
| `md5sum input.pcap` | `cf23235a67009ec42f7aea827ef38b5b` |
| `sha256 input.pcap` (script in ra) | `0122cb1c0116703b5ef81b890cf7403aa89fc6d165e3b654a97bec846b45a14d` |

## 1. Kịch bản

Hai packet, giống nhau từng byte trừ `seq`: SYN thuần từ `10.10.0.10:43210` tới `10.20.0.10:80` ở
giây 0, rồi **đúng cùng 5-tuple** ở giây 3. Không có SYN/ACK trả lời ở giữa.

Đây là hình dạng của một SYN không ai nhận, rồi client thử lại từ port cũ. Chạy với
`--set tcp.new=1`, thứ cần kiểm là: flow thứ nhất **rời bảng** vì im lặng quá ngưỡng, và packet thứ
hai **mở flow mới** chứ không hồi sinh flow cũ (REQ-33.6, 30.6). `flow_id` khác nhau là bằng chứng
cho "mới" — nếu tracker hồi sinh flow cũ thì `flows.jsonl` chỉ có một dòng `packet_count` = 2.

Hai lựa chọn khi dựng PCAP, cả hai đều có lý do:

- **Hai packet đều là SYN thuần.** Ngưỡng im lặng tra theo **trạng thái** flow, không phải một con số
  chung (`_TCP_IDLE` trong `idps/process/flow.py`): `HANDSHAKE` → `tcp.new`, `ESTABLISHED` →
  `tcp.established` = 3600 s. Nếu packet đầu là `PSH+ACK` thì flow vào `ESTABLISHED` và khoảng 3 s
  không đủ để hết hạn — ca test im lặng mà vẫn "pass". Trạng thái `HANDSHAKE` cũng là chỗ duy nhất
  cho ra `close_reason` = `idle_new`, đúng giá trị điều kiện dừng đòi.
- **PCAP dựng tay, không bắt thật.** Thứ cần đo là một **khoảng im lặng** có độ dài biết trước. Bắt
  thật thì khoảng đó do `sleep` và kernel quyết định (3,0xx s lần này, 3,1xx s lần sau), và nếu kernel
  tự truyền lại SYN trong 3 giây đó thì khoảng im lặng bị chen mất — ca test hỏng mà không ai thấy.
  Dựng tay thì `last_seen` và `now` là hai hằng số, nên điều kiện `now − last_seen > tcp.new` kiểm
  đúng chỗ nó cần kiểm.

## 2. Lệnh tái hiện

`input.pcap` đã commit, nên chỉ cần **một** dòng lệnh để dựng lại toàn bộ bằng chứng:

```sh
export HOST_UID=$(id -u) HOST_GID=$(id -g); TC=TEST/T12_idle-timeout; docker compose run --rm idps-offline python main.py --pcap $TC/input.pcap -o $TC/output.jsonl --flow-output $TC/flows.jsonl --set tcp.new=1 > /tmp/raw.log 2>&1; code=$?; grep -v '^ *Container ' /tmp/raw.log > $TC/run.log; echo "exit=$code" >> $TC/run.log
```

Sinh lại `input.pcap` từ script (output tất định, `sha256` ở bảng trên — chạy lại không làm
`git status` khác):

```sh
python tests/tools/make_timeout_pcap.py
```

## 3. Kết quả mong đợi

Điều kiện dừng T7.2: exit 0; chạy lại khớp **từng byte**; `flows.jsonl` có **hai** dòng `flow_id`
khác nhau; dòng đầu `close_reason` = `idle_new`; `run.log` có **đúng một** dòng `config=` chứa
`"tcp.new":1`.

Nhánh hỏng hay gặp:

- **một** dòng flow, `packet_count` = 2 → hoặc `--set` không tới được tracker (vẫn chạy ngưỡng 60 s),
  hoặc bước hết hạn chạy **sau** khi gán packet nên packet 2 kịp vào flow cũ.
- hai dòng nhưng dòng đầu `close_reason` = `end_of_run` → flow 1 không bị hết hạn, nó chỉ bị đóng ở
  bước cuối lần chạy; packet 2 mở flow mới vì lý do khác (khoá flow tính cả `seq` chẳng hạn).
- dòng đầu `close_reason` = `idle_established` → ngưỡng tra theo một con số chung thay vì theo trạng
  thái, hoặc một SYN thuần đã bị tính là kết nối thiết lập.
- `run.log` **không** có dòng `config=`, hoặc có nhưng in `"tcp.new":60` → bằng chứng đã commit không
  tự giải thích được vì sao flow hết hạn (REQ-36.4), người đọc lại phải tin vào README.

## 4. Kết quả thực tế

```
$ cat run.log
config={"max_active_flows":10000,...,"tcp.closed":120,"tcp.established":3600,"tcp.new":1,...}
processed=2 unknown=0 malformed=0
flows_created=2 flows_closed=2 close.idle_new=1 close.end_of_run=1 decode_errors=0 preprocess_errors=0 flow_errors=0
exit=0
```

Hai event (`output.jsonl`), cùng 5-tuple, **khác** `flow_id`:

| # | `timestamp` | `flow.flow_id` | `flow.direction` | `flow.state` |
|---|---|---|---|---|
| 1 | `2026-09-28T00:00:00.000000Z` | 1 | forward | `HANDSHAKE` |
| 2 | `2026-09-28T00:00:03.000000Z` | 2 | forward | `HANDSHAKE` |

Hai flow record (`flows.jsonl`):

| `flow_id` | `packet_count` | `start_time` | `last_seen` | `close_time` | `duration_usec` | `state` | `close_reason` |
|---|---|---|---|---|---|---|---|
| 1 | 1 | `…00:00:00` | `…00:00:00` | `…00:00:03` | 0 | `HANDSHAKE` | `idle_new` |
| 2 | 1 | `…00:00:03` | `…00:00:03` | `…00:00:03` | 0 | `HANDSHAKE` | `end_of_run` |

Cả hai có `syn_count` = 1, `application_protocol` = `null` (một SYN trơn không có payload nên không
có gì để nhận giao thức ứng dụng), `midstream` = `false`.

Chạy **cùng** PCAP mà **không** `--set` (ngưỡng mặc định `tcp.new` = 60 s):

```
config={...,"tcp.new":60,...}
processed=2 unknown=0 malformed=0
flows_created=1 flows_closed=1 close.end_of_run=1 ...
```

→ **một** flow, `packet_count` = 2, `duration_usec` = 3 000 000. Cùng tệp vào, hai kết quả khác nhau,
và dòng `config=` là chỗ duy nhất phân biệt được hai lần chạy — đó là lý do REQ-36.4 đòi in cấu hình
**sau khi** đã áp `--set` chứ không in giá trị mặc định.

## 5. Nhận xét

- **Không chờ 60 giây thật nào.** "Bây giờ" của tracker là `timestamp` của packet đang xử lý
  (REQ-33.2), không phải giờ hệ thống: `_advance_clock` đặt `now = max(now, ts)`. Khoảng im lặng vì
  vậy là một phép trừ giữa hai con số **trong tệp**, và một PCAP dài 3 s có thể chứa khoảng im lặng
  tuỳ ý — chỉ cần ghi timestamp cách nhau đủ xa. Lấy đồng hồ hệ thống thì chạy lại cùng một PCAP ở
  hai thời điểm khác nhau cho hai kết quả khác nhau, output mất tính tất định (I-21), và chế độ PCAP
  sẽ đóng hết flow ngay packet đầu nếu tệp được bắt từ hôm trước.
- **`duration_usec` = 0 nhưng `close_time − start_time` = 3 s.** Flow 1 chỉ thấy **một** packet, nên
  thời lượng thật của nó bằng 0: `duration_usec` = `last_seen_usec − start_time_usec` (REQ-34.4).
  `close_time` là lúc bản ghi **rời bảng**, mà việc rời bảng được phát hiện khi packet 2 tới — nên nó
  mang timestamp của packet 2. Hai đại lượng trả lời hai câu hỏi khác nhau: "phiên kéo dài bao lâu"
  và "bản ghi chốt sổ lúc nào".
- **Hết hạn phải xét *trước* khi gán packet.** `FlowTracker.process` gọi `table.expire(...)` ngay sau
  khi cập nhật đồng hồ, trước `get_or_create`. Nếu đảo thứ tự thì packet 2 cập nhật `last_seen` của
  flow 1 trước, flow 1 không còn im lặng, và timeout không bao giờ xảy ra — bug này âm thầm vì mọi
  thứ khác vẫn đúng, chỉ có `flows.jsonl` ra một dòng thay vì hai.
- **Flow 1 vẫn được xuất ra `flows.jsonl` trước khi rời bảng** (I-18). Nếu chỉ xoá khỏi bảng thì một
  packet đã xử lý không còn truy được về bản ghi nào: `1 + 1 = 2` = `processed`, tổng này là cách
  kiểm nhanh rằng không có flow nào bị bỏ im lặng.
- **`state` của flow 1 vẫn là `HANDSHAKE` trong record.** Hết hạn không phải là đóng kết nối: không
  có FIN nào, nên trạng thái cuối cùng quan sát được đúng là `HANDSHAKE`. Ghi `CLOSED` ở đây là bịa
  ra một điều không thấy trên dây — và sẽ làm luật phát hiện quét cổng ở bài sau mất đúng cái nó cần
  (một dãy flow `HANDSHAKE` hết hạn với `close_reason` = `idle_new`).
