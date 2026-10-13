#!/usr/bin/env python3
"""T7.2 — sinh PCAP cho T12 (idle timeout): hai SYN cùng 5-tuple, cách nhau 3 s.

**Vì sao phải dựng thay vì bắt thật.** Thứ cần kiểm ở T12 là một **khoảng im
lặng** có độ dài biết trước. Bắt thật thì khoảng đó do kernel và `sleep` quyết
định: `sleep 3` cho 3,0xx s, lần sau 3,1xx s, và nếu client truyền lại SYN giữa
hai mốc thì khoảng im lặng bị chen mất. Dựng tay thì `last_seen` và `now` là hai
con số ta tự đặt, nên điều kiện `now - last_seen > tcp.new` kiểm được **đúng**
chỗ nó cần kiểm, không phải chỗ gần đúng.

**Vì sao hai packet đều là SYN thuần.** Ngưỡng im lặng tra theo **trạng thái**
(`idps/process/flow.py` `_TCP_IDLE`): một SYN chưa được trả lời để flow ở
`HANDSHAKE`, ứng với `tcp.new` và `close_reason` = `idle_new`. Nếu packet thứ
nhất là `PSH+ACK` thì flow vào `ESTABLISHED`, ngưỡng thành `tcp.established` =
3600 s và khoảng 3 s không đủ để hết hạn — ca test im lặng mà vẫn "pass".
Hình dạng này cũng có thật: một SYN không ai trả lời rồi client thử lại từ đúng
port cũ.

**Vì sao gap = 3 s chứ không phải 61 s.** Cả hai đều chạy được, vì "bây giờ" của
tracker lấy từ timestamp packet (REQ-33.2) nên không có giây thật nào bị chờ.
Chọn 3 s để con số trong tệp không ngụ ý ngưỡng mặc định: muốn flow hết hạn thì
phải hạ ngưỡng bằng `--set tcp.new=1`, và dòng `config=` trong `run.log` nói ra
điều đó (REQ-36.4). Dùng 61 s thì ca test đúng vì một lý do không ai đọc được
trong log.

**Tất định:** timestamp là hằng số, không có `time.time()` hay số ngẫu nhiên.
Chạy hai lần → `sha256sum` giống nhau (I-21).

Chạy:  python tests/tools/make_timeout_pcap.py          # ghi vào TEST/
       python tests/tools/make_timeout_pcap.py --check  # in sha256, không ghi
"""
import argparse
import hashlib
import struct
from pathlib import Path

# Chạy script trực tiếp thì Python đặt thư mục của nó vào sys.path[0], nên
# import này tìm thấy file bên cạnh bất kể cwd. Dùng lại bộ ghép header thay vì
# copy: hai script dựng PCAP của bài phải sinh ra cùng một dạng frame, và chỗ
# duy nhất T12 cần khác là timestamp của từng bản ghi.
from make_bad_pcaps import (BASE_TS_SEC, LINKTYPE_ETHERNET, PCAP_MAGIC,
                            PCAP_VERSION, SNAPLEN, ethernet, ipv4, tcp)

FLAG_SYN = 0x02                 # SYN thuần: không kèm ACK -> mở HANDSHAKE
GAP_SEC = 3                     # khoảng im lặng giữa hai packet
CLIENT_PORT = 43210             # cùng port ở cả hai packet -> CÙNG 5-tuple

_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")


def pcap_bytes(records):
    """[(ten, ts_usec_tuong_doi, data)] -> bytes của cả file PCAP.

    Khác `pcap_bytes` của `make_bad_pcaps`: ở đó timestamp chỉ cần tăng dần để
    đọc được thứ tự, ở đây **khoảng cách** giữa hai mốc là dữ liệu của ca test,
    nên mỗi bản ghi mang mốc riêng do hàm gọi truyền vào.
    """
    out = [_GLOBAL_HEADER.pack(PCAP_MAGIC, *PCAP_VERSION, 0, 0, SNAPLEN,
                               LINKTYPE_ETHERNET)]
    for _name, offset_usec, data in records:
        sec, usec = divmod(offset_usec, 1_000_000)
        out.append(_RECORD_HEADER.pack(BASE_TS_SEC + sec, usec,
                                       len(data), len(data)))
        out.append(data)
    return b"".join(out)


def t12_records():
    """Hai SYN giống nhau từng byte trừ `seq`, cách nhau GAP_SEC giây.

    `seq` khác nhau để hai packet không phải bản sao hệt nhau — một SYN truyền
    lại thật cũng giữ nguyên seq, nhưng một lần thử kết nối MỚI thì sinh seq
    mới, và đó là thứ ca này mô tả (flow cũ đã hết hạn, không phải cùng phiên).
    """
    syn = lambda seq: ethernet(ipv4(tcp(sport=CLIENT_PORT, dport=80,
                                        flags=FLAG_SYN, seq=seq, ack=0)))
    return [
        ("syn-1", 0, syn(1000)),
        ("syn-2-after-gap", GAP_SEC * 1_000_000, syn(5000)),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", default="TEST", type=Path,
                        help="thư mục gốc chứa TEST/T12_… (mặc định TEST)")
    parser.add_argument("--check", action="store_true",
                        help="chỉ in sha256 và bảng packet, không ghi file")
    args = parser.parse_args()

    records = t12_records()
    blob = pcap_bytes(records)
    path = args.out_dir / "T12_idle-timeout/input.pcap"
    if not args.check:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    print(f"{'(check) ' if args.check else ''}{path}  "
          f"linktype={LINKTYPE_ETHERNET}  {len(records)} record  {len(blob)} byte")
    print(f"    sha256 {hashlib.sha256(blob).hexdigest()}")
    for index, (name, offset_usec, data) in enumerate(records, start=1):
        print(f"    {index:2}. {name:20} t=+{offset_usec / 1_000_000:.6f}s  "
              f"{len(data)} byte")


if __name__ == "__main__":
    main()
