#!/usr/bin/env python3
"""T10.1 — sinh PCAP dựng tay cho TC-11 (UNKNOWN) và TC-12 (malformed).

**Vì sao hai test case này phải dùng PCAP dựng thay vì bắt thật (ADR-11):** mọi
packet ở đây là thứ mà một hệ điều hành **không chịu tạo ra**. Kernel Linux không
gửi một packet khai `IHL = 3`, `nc` không gửi UDP có `length` sai, và không có
cách nào bảo `dnsmasq` trả một con trỏ nén tự trỏ vào chính nó. Muốn có chúng thì
phải tự ghép từng byte — và đó cũng chính là cách kẻ tấn công tạo ra chúng.

**Vì sao chỉ dùng `struct`, không dùng Scapy** (dù Scapy đã có trong image): mỗi
trường ở đây phải đặt được **giá trị SAI** một cách có chủ đích. Scapy được thiết
kế để làm ngược lại — nó tự tính `len`, `ihl`, checksum, và phải chống lại nó
(`del pkt.len`, `pkt.ihl = 3` rồi `bytes(pkt)`) thì rối hơn là tự ghép. Tự ghép
còn có một lợi ích cho việc học: script này chỉ dùng đúng những con số mà
`design.md` §5.4 và các parser đọc, nên đọc script là thấy lại cấu trúc header.

**Tất định (điều kiện dừng T10.1):** không có `time.time()`, không có số ngẫu
nhiên, không có thứ tự dict nào ảnh hưởng output. Chạy hai lần → `sha256sum`
giống nhau, nên `git diff` trên file bằng chứng chỉ khác khi nội dung THẬT đổi.

**Checksum để 0 ở mọi header.** Ba parser của bài cố tình KHÔNG kiểm checksum
(lý do đầy đủ ở `idps/decode/ipv4.py`: card mạng tính checksum bằng phần cứng nên
packet bắt trên chính máy gửi thường có checksum 0 hoặc sai). Đặt 0 vì thế không
tạo ra lỗi ngoài ý muốn, và nó cũng đúng là thứ hay thấy trên dây thật.

Chạy:  python tests/tools/make_bad_pcaps.py            # ghi vào TEST/
       python tests/tools/make_bad_pcaps.py --check    # in sha256, không ghi
"""
import argparse
import hashlib
import struct
from pathlib import Path

# --- vỏ file PCAP cổ điển (Phụ lục D) ---------------------------------------

# Magic 0xA1B2C3D4 = PCAP cổ điển, timestamp phần lẻ tính bằng MICRO giây, và
# việc đọc nó theo big-endian hay little-endian do chính 4 byte này quyết định
# (file ghi ngược thì đầu đọc thấy 0xD4C3B2A1). Ta ghi little-endian vì đó là
# thứ tcpdump trên x86 sinh ra, nên file dựng và file bắt thật cùng một dạng.
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
SNAPLEN = 262144                # đúng mặc định của tcpdump hiện nay
LINKTYPE_ETHERNET = 1           # DLT_EN10MB — loại duy nhất bài 1 hỗ trợ
LINKTYPE_LINUX_SLL = 113        # "cooked" của `tcpdump -i any`; bài 1 chưa hỗ trợ

# 2026-09-28T00:00:00Z. Một hằng số thay cho thời điểm chạy script -> output tất
# định. Mỗi packet lấy một mốc micro giây riêng để thứ tự trong file đọc được.
BASE_TS_SEC = 1790553600

_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")


def pcap_bytes(linktype, records):
    """[(ten, data, cut_bytes)] -> bytes của cả file PCAP.

    `cut_bytes` > 0 = bản ghi CUỐI bị cắt: phần header vẫn khai đủ `incl_len`
    byte nhưng file chỉ còn ít hơn thế. Đây là cách duy nhất tạo ca REQ-2.5
    (tcpdump bị kill giữa lúc ghi) mà không phải thật sự kill tcpdump.
    """
    out = [_GLOBAL_HEADER.pack(PCAP_MAGIC, *PCAP_VERSION, 0, 0, SNAPLEN,
                               linktype)]
    for index, (_name, data, cut) in enumerate(records):
        # incl_len KHAI độ dài đầy đủ; nếu cut > 0 thì phần ghi thật ngắn hơn.
        out.append(_RECORD_HEADER.pack(BASE_TS_SEC, index * 1000,
                                       len(data), len(data)))
        out.append(data[:len(data) - cut] if cut else data)
    return b"".join(out)


# --- tầng liên kết và tầng mạng ---------------------------------------------

MAC_ATTACKER = bytes.fromhex("02420a0a000a")     # 02:42:… = MAC do Docker đặt
MAC_SENSOR = bytes.fromhex("02420a0a00fe")
IP_ATTACKER = bytes([10, 10, 0, 10])
IP_VICTIM = bytes([10, 20, 0, 10])

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_GRE = 47


def ethernet(payload, ethertype=ETHERTYPE_IPV4):
    """14 byte: dst MAC + src MAC + EtherType. EtherType là trường duy nhất
    chỉ ra tầng trên — khác TCP/UDP không có trường nào như thế (xem detector)."""
    return struct.pack("!6s6sH", MAC_SENSOR, MAC_ATTACKER, ethertype) + payload


def ipv4(payload, proto=PROTO_TCP, ihl=5, total_length=None, ttl=64,
         identification=0x1234, flags_fragment=0x4000):
    """20 byte header + payload. `ihl` và `total_length` mở ra để đặt SAI.

    flags_fragment mặc định 0x4000 = cờ DF, offset 0 (packet không phân mảnh).
    total_length=None -> khai đúng; truyền số khác -> đúng ca "khai quá dài".
    """
    header_words = ihl                      # đơn vị 4 byte, giá trị đúng là 5
    version_ihl = (4 << 4) | header_words
    if total_length is None:
        total_length = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s",
                       version_ihl, 0, total_length, identification,
                       flags_fragment, ttl, proto, 0,   # 0 = checksum
                       IP_ATTACKER, IP_VICTIM) + payload


# --- tầng transport ---------------------------------------------------------

FLAG_PSH_ACK = 0x18


def tcp(payload=b"", sport=40470, dport=80, data_offset=5, flags=FLAG_PSH_ACK,
        seq=1000, ack=2000):
    """20 byte header + payload. `data_offset` mở ra để đặt SAI (đơn vị 4 byte).

    data_offset = 5 là đúng khi không có option. 2 là vô nghĩa (nhỏ hơn cả
    header cố định); 15 khai header 60 byte, nếu segment ngắn hơn thì phần
    "option" đó không tồn tại.
    """
    offset_reserved = (data_offset << 4)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                       offset_reserved, flags, 8192, 0, 0) + payload


def udp(payload=b"", sport=40470, dport=53, length=None):
    """8 byte header + payload. `length` là ĐỘ DÀI CẢ HEADER + payload (không
    phải chỉ payload) — đây là chỗ hay nhầm, và cũng là trường đem đặt sai."""
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


# --- tầng ứng dụng: DNS dựng tay --------------------------------------------

def dns_name(*labels):
    """("victim","lab") -> b"\\x06victim\\x03lab\\x00". Tên trên dây KHÔNG có dấu
    chấm: dấu phân cách là byte độ dài đứng trước mỗi nhãn."""
    out = b""
    for label in labels:
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_header(ident=0x1234, flags=0x8180, qdcount=1, ancount=1):
    return struct.pack("!HHHHHH", ident, flags, qdcount, ancount, 0, 0)


QUESTION = dns_name("victim", "lab") + struct.pack("!HH", 1, 1)   # A, IN


def dns_pointer_loop():
    """Response có question HỢP LỆ, answer mang con trỏ TỰ TRỎ VÀO CHÍNH NÓ.

    Vị trí con trỏ phải tính ra: 12 byte header + len(QUESTION). Con trỏ 2 byte
    `C0 xx` đặt ĐÚNG tại offset đó và trỏ về chính offset đó -> parser đọc tên,
    nhảy tới đó, lại thấy con trỏ, lại nhảy... Vòng lặp vô hạn nếu không có tập
    `seen` (I-6).

    Question phải hợp lệ là điều kiện BẮT BUỘC, không phải tuỳ ý: chữ ký Phụ
    lục C = "parse được trọn phần question". Nếu đặt con trỏ xấu trong question
    thì detector không nhận ra DNS và event ra `UNKNOWN`/`ok` chứ không phải
    `malformed` — ranh giới đã chốt ở V8.1 (design ADR-5).
    """
    offset = 12 + len(QUESTION)
    assert offset < 0x3FFF, "offset phải vừa trong 14 bit của con trỏ"
    pointer = struct.pack("!H", 0xC000 | offset)
    answer = pointer + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, 20, 0, 10])
    return dns_header() + QUESTION + answer


def dns_ancount_too_big():
    """ANCOUNT khai 5 nhưng chỉ có 1 answer thật -> REQ-8.5: giữ answer đã đọc
    được rồi báo lỗi khi hết byte ở answer thứ 2."""
    answer = (b"\xc0\x0c"                          # tên nén, trỏ về question
              + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, 20, 0, 10]))
    return dns_header(ancount=5) + QUESTION + answer


# --- TC-11: giao thức chưa hỗ trợ (REQ-17.2, 17.3) --------------------------

def tc11_records():
    """Năm packet, mỗi packet dừng ở MỘT tầng khác nhau — để `output.jsonl`
    chứng minh được rằng `UNKNOWN` xuất hiện đúng ở tầng không hiểu được, và
    các tầng dưới nó vẫn được điền đủ (REQ-14.1)."""
    # ARP request: EtherType 0x0806. Frame parse xong, tầng mạng chưa hỗ trợ.
    arp = struct.pack("!HHBBH6s4s6s4s",
                      1, ETHERTYPE_IPV4, 6, 4, 1,          # Ethernet/IPv4, request
                      MAC_ATTACKER, IP_ATTACKER,
                      bytes(6), IP_VICTIM)
    # IPv6: chỉ cần 40 byte header là đủ để chứng minh EtherType không phải IPv4.
    ipv6 = (struct.pack("!IHBB", 0x60000000, 8, 58, 64)     # 58 = ICMPv6
            + bytes(16) + bytes(16) + bytes(8))
    # ICMP echo request: IPv4 hợp lệ, protocol 1 -> transport chưa hỗ trợ.
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"abcdefgh"
    # GRE: protocol 47. Cùng lý lẽ với ICMP nhưng không phải giao thức "quen",
    # để thấy bảng TRANSPORT_PARSERS là một tra cứu chứ không phải danh sách if.
    gre = struct.pack("!HH", 0, ETHERTYPE_IPV4) + bytes(8)
    # SSH trên TCP 22: cả ba tầng dưới hợp lệ, chỉ tầng ứng dụng không có chữ ký
    # nào khớp -> app_proto UNKNOWN, app null, status vẫn "ok" (ADR-14).
    ssh = tcp(b"SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n", sport=40470, dport=22)
    return [
        ("arp-request", ethernet(arp, ETHERTYPE_ARP), 0),
        ("ipv6-header", ethernet(ipv6, ETHERTYPE_IPV6), 0),
        ("icmp-echo", ethernet(ipv4(icmp, proto=PROTO_ICMP)), 0),
        ("ipv4-proto-47-gre", ethernet(ipv4(gre, proto=PROTO_GRE)), 0),
        ("ssh-banner-on-tcp-22", ethernet(ipv4(ssh)), 0),
    ]


def tc11_linktype_records():
    """File riêng: linktype 113 (LINUX_SLL) thay vì 1 (Ethernet).

    Phải là file RIÊNG vì linktype nằm trong **global header** của PCAP — một
    file chỉ có đúng một linktype. Nội dung bên trong là một frame SLL bọc IPv4
    hợp lệ, nên nếu về sau bài hỗ trợ SLL thì file này vẫn dùng được.
    """
    sll = (struct.pack("!HHH8sH", 0, 1, 6, MAC_ATTACKER + bytes(2),
                       ETHERTYPE_IPV4)
           + ipv4(tcp(b"GET / HTTP/1.1\r\n\r\n")))
    return [("linux-sll-frame", sll, 0)]


# --- TC-12: packet hỏng (REQ-15, NFR-1) -------------------------------------

def tc12_records():
    """Chín packet hỏng + một bản ghi bị cắt, đúng danh sách design §9.

    Mỗi packet hỏng ĐÚNG MỘT chỗ: tầng dưới nó luôn hợp lệ. Nhờ vậy
    `errors[].layer` trong output chỉ ra được chính xác parser nào bắt được lỗi,
    và nếu một packet cho ra lỗi ở tầng khác dự kiến thì đó là bug thật, không
    phải do payload dựng nhập nhèm.
    """
    http_binary_header = (b"GET / HTTP/1.1\r\n"
                          b"Host: 10.20.0.10\r\n"
                          b"X-Evil: \xff\xfe binary\r\n\r\n")
    return [
        # 1. Ethernet hợp lệ, nhưng chỉ có 12 byte cho header IPv4 (cần 20).
        ("ipv4-truncated-header", ethernet(bytes(range(12))), 0),
        # 2. IHL = 3 -> khai header dài 12 byte, nhỏ hơn cả 20 byte cố định.
        ("ipv4-ihl-3", ethernet(ipv4(tcp(), ihl=3)), 0),
        # 3. total_length khai 200 nhưng frame chỉ mang 40 byte IPv4.
        ("ipv4-total-length-too-big",
         ethernet(ipv4(tcp(), total_length=200)), 0),
        # 4. TCP data offset = 2 -> khai header 8 byte, nhỏ hơn 20 byte cố định.
        ("tcp-data-offset-2", ethernet(ipv4(tcp(data_offset=2))), 0),
        # 5. TCP data offset = 15 -> khai header 60 byte trên một segment chỉ
        #    có 20 byte: phần option được khai không tồn tại.
        ("tcp-data-offset-15", ethernet(ipv4(tcp(data_offset=15))), 0),
        # 6. UDP length khai 100 nhưng datagram chỉ có 8 + 5 = 13 byte.
        ("udp-length-too-big",
         ethernet(ipv4(udp(b"hello", length=100), proto=PROTO_UDP)), 0),
        # 7. DNS: con trỏ nén tự trỏ vào chính nó (REQ-8.4, I-6).
        ("dns-pointer-loop",
         ethernet(ipv4(udp(dns_pointer_loop(), sport=53, dport=40470),
                       proto=PROTO_UDP)), 0),
        # 8. DNS: ANCOUNT = 5 nhưng chỉ có 1 answer (REQ-8.5).
        ("dns-ancount-too-big",
         ethernet(ipv4(udp(dns_ancount_too_big(), sport=53, dport=40470),
                       proto=PROTO_UDP)), 0),
        # 9. HTTP: request line hợp lệ (nên detector NHẬN ra HTTP) nhưng một
        #    dòng header chứa byte 0xFF -> REQ-7.5.
        ("http-binary-header",
         ethernet(ipv4(tcp(http_binary_header))), 0),
        # 10. Bản ghi CUỐI bị cắt 6 byte: header khai đủ, file hết sớm (REQ-2.5).
        ("pcap-record-truncated",
         ethernet(ipv4(tcp(b"GET / HTTP/1.1\r\n\r\n"))), 6),
    ]


# --- ghi file ---------------------------------------------------------------

FILES = (
    ("TC-11_unknown-protocol/input.pcap", LINKTYPE_ETHERNET, tc11_records),
    ("TC-11_unknown-protocol/input-linktype.pcap", LINKTYPE_LINUX_SLL,
     tc11_linktype_records),
    ("TC-12_malformed-packet/input.pcap", LINKTYPE_ETHERNET, tc12_records),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", default="TEST", type=Path,
                        help="thư mục gốc chứa các TEST/TC-xx_… (mặc định TEST)")
    parser.add_argument("--check", action="store_true",
                        help="chỉ in sha256 và bảng packet, không ghi file")
    args = parser.parse_args()

    for relative, linktype, build in FILES:
        records = build()
        blob = pcap_bytes(linktype, records)
        digest = hashlib.sha256(blob).hexdigest()
        path = args.out_dir / relative
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
        print(f"{'(check) ' if args.check else ''}{path}  "
              f"linktype={linktype}  {len(records)} record  {len(blob)} byte")
        print(f"    sha256 {digest}")
        for index, (name, data, cut) in enumerate(records, start=1):
            note = f"  [bản ghi bị cắt {cut} byte]" if cut else ""
            print(f"    {index:2}. {name:26} {len(data) - cut:4} byte{note}")


if __name__ == "__main__":
    main()
