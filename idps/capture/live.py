"""LiveSource — bắt packet trực tiếp trên một interface (REQ-1, ADR-2).

Cùng hợp đồng với PcapSource: `LiveSource(iface).frames()` -> Iterator[RawFrame],
mọi lý do "không mở được nguồn" đều thành SourceError. Nhờ vậy Runner và main.py
không có một dòng nào phân biệt live với pcap (REQ-3.1, REQ-3.2).

Vì sao dùng SOCKET của Scapy (`conf.L2listen`) chứ không `sniff()`:
ADR-2 chốt "Scapy chỉ làm ống dẫn, không dùng kết quả bóc tách của nó" — ở đây
vẫn đúng nguyên tắc đó, chỉ khác chỗ lấy bytes ra khỏi ống:

1. `sniff()` là mô hình ĐẨY (gọi lại `prn` cho từng packet). Hợp đồng §6 lại là
   mô hình KÉO (`for frame in source.frames()`). Ghép đẩy vào kéo cần một thread
   + một hàng đợi; thêm thread chỉ để đảo chiều điều khiển là thêm đúng một loại
   bug (hàng đợi đầy, thread chết im lặng) mà không đổi được gì về kết quả.
2. `sniff()` dissect từng packet rồi ta lấy `bytes(pkt)` — tức bytes được Scapy
   DỰNG LẠI từ các trường nó hiểu (rủi ro R1 ở design §11). `recv_raw()` trả
   đúng bytes kernel giao. Với một IDS, chênh một byte giữa "cái trên dây" và
   "cái đã parse" là mất chính thứ đang cần đo.
3. Không dissect còn có nghĩa Scapy không phải bóc tách dữ liệu do kẻ tấn công
   kiểm soát (§8.3) — bớt một bề mặt tấn công, bớt CPU.

Đây vẫn là phương án B của ADR-2 (Scapy làm ống dẫn), KHÔNG phải phương án C
(tự mở AF_PACKET và tự đọc bằng struct): việc mở socket, đặt SO_TIMESTAMPNS và
lấy nhãn thời gian của kernel đều do Scapy làm. R1 ở §11 nêu sẵn `recv_raw` là
phương án thay thế khi `bytes(pkt)` lệch bytes trên dây.
"""
import logging

from scapy.config import conf
from scapy.error import Scapy_Exception

# Import vì TÁC DỤNG PHỤ: scapy.config chỉ khai báo conf.L2listen = None, phải
# nạp tầng arch thì nó mới được gán lớp socket của nền tảng đang chạy. Thiếu
# dòng này thì conf.L2listen là None và lỗi chỉ lộ ra lúc gọi.
import scapy.arch  # noqa: F401

from ..core.frame import RawFrame
from . import SourceError

_SYS_NET = "/sys/class/net"

# /sys/class/net/<iface>/type là ARPHRD_* của kernel, KHÔNG phải LINKTYPE_* của
# PCAP — hai không gian số khác nhau, trùng nhau ở số 1 nên rất dễ nhầm.
# ARPHRD_ETHER (1) và ARPHRD_LOOPBACK (772) đều mang frame Ethernet (trên lo,
# header Ethernet có thật, chỉ toàn MAC 00:00:00:00:00:00) -> cùng LINKTYPE 1
# (ADR-2). Interface khác (tun, ppp, 802.11...) không nằm trong phạm vi bài này.
_ARPHRD_TO_LINKTYPE = {1: 1, 772: 1}

_USEC_PER_SEC = 1_000_000

# Số byte tối đa nhận cho một frame. 65535 = mặc định của tcpdump, và lớn hơn
# MTU 1500 của lab -> không frame nào bị cắt. Dùng cùng giá trị với tcpdump để
# file PCAP đối chứng ở T11.1 chứa đúng những byte mà bản live đã thấy.
_SNAPLEN = 65535

# Logger mà Scapy dùng cho cảnh báo lúc chạy (scapy/error.py).
_SCAPY_RUNTIME_LOG = "scapy.runtime"


def _drop_link_layer_guess_warning(record) -> bool:
    """Bỏ đúng MỘT cảnh báo của Scapy: "Unable to guess type (interface=...)".

    Lúc mở socket, Scapy tra ARPHRD của interface trong conf.l2types để biết
    nên gán lớp nào cho self.LL — cái tên lớp mà recv() sẽ dùng để dissect.
    Bảng đó chỉ được điền khi nạp scapy.layers.*, mà ta CỐ Ý không nạp
    (ADR-2: không dùng dissector của Scapy). Nên cảnh báo này đúng là hệ quả
    mong muốn của thiết kế, và nó nói về một thuộc tính ta không bao giờ đọc:
    recv_raw() trả bytes thô, không dùng self.LL.

    Lọc thay vì hạ mức cả logger: cảnh báo thật của Scapy vẫn phải hiện ra.
    Lọc theo nội dung thay vì nạp thêm scapy.layers.l2: không kéo bộ dissect
    vào chương trình chỉ để một dòng log im đi.
    """
    return not record.getMessage().startswith("Unable to guess type")


class LiveSource:
    """Nguồn packet đọc từ interface. Kiểm tra interface ngay trong __init__.

    Cùng lý do như PcapSource: frames() là generator nên thân hàm chưa chạy
    cho tới next() đầu tiên. Nếu để việc kiểm tra ở đó thì main.py đã mở xong
    file output rồi mới biết interface không tồn tại (REQ-1.4, REQ-20.4).
    """

    def __init__(self, iface):
        self.iface = str(iface)
        # Tên interface đi thẳng vào một đường dẫn dưới /sys -> chặn ký tự có
        # nghĩa với đường dẫn. Tên interface của Linux không bao giờ chứa "/"
        # (IFNAMSIZ 16 ký tự, không có dấu phân cách), nên đây không phải giới
        # hạn giả: "int0/../../etc" chỉ có thể là gõ sai hoặc cố tình.
        if "/" in self.iface or self.iface in ("", ".", ".."):
            raise SourceError(f"invalid interface name: {self.iface!r}")
        self.linktype = self._read_linktype()

    def _read_linktype(self) -> int:
        """LINKTYPE suy từ ARPHRD của interface (REQ-1.4, ADR-2).

        Đọc từ /sys thay vì hỏi Scapy: đây là con số đi vào MỌI event của lần
        chạy (design §5.1), nên lấy thẳng từ kernel rồi tự dịch, và cũng là chỗ
        phát hiện "interface không tồn tại" bằng đúng một lần mở file.
        """
        path = f"{_SYS_NET}/{self.iface}/type"
        try:
            with open(path, encoding="ascii") as f:
                arphrd = int(f.read().strip())
        except FileNotFoundError as exc:
            # REQ-1.4: thông báo phải nêu tên interface để người chạy sửa được
            # ngay, không bắt họ đoán từ một traceback.
            raise SourceError(f"no such interface: {self.iface}") from exc
        except OSError as exc:
            raise SourceError(f"cannot read link type of {self.iface}: {exc}") from exc
        except ValueError as exc:
            raise SourceError(f"bad link type of {self.iface}: {exc}") from exc

        if arphrd not in _ARPHRD_TO_LINKTYPE:
            # Thà dừng còn hơn parse sai: mọi parser phía sau đang giả định
            # frame mở đầu bằng 14 byte Ethernet (REQ-17.2).
            raise SourceError(
                f"unsupported interface type of {self.iface}: ARPHRD {arphrd}"
            )
        return _ARPHRD_TO_LINKTYPE[arphrd]

    def _open(self):
        """Mở socket nghe tầng 2. Mọi lỗi mở -> SourceError (REQ-1.5, 18.5)."""
        log = logging.getLogger(_SCAPY_RUNTIME_LOG)
        log.addFilter(_drop_link_layer_guess_warning)
        try:
            # promisc=False: sensor là gateway, frame cần bắt ĐÃ gửi tới MAC của
            # nó (gói đi qua router mang MAC đích của router) hoặc do chính nó
            # gửi ra, nên không cần bật chế độ nhận mọi frame. Mặc định của
            # Scapy là True -> phải tắt tường minh (least privilege, §8.3).
            return conf.L2listen(iface=self.iface, promisc=False)
        except PermissionError as exc:
            # REQ-1.5, REQ-18.5: mở AF_PACKET cần CAP_NET_RAW. Chạy trong
            # idps-offline (cap_drop: ALL) là errno EPERM ngay ở đây — phải nói
            # rõ là thiếu quyền, kèm tên service đúng, chứ không im lặng treo.
            raise SourceError(
                f"no permission to capture on {self.iface} ({exc}); "
                "live capture needs CAP_NET_RAW (service idps), not idps-offline"
            ) from exc
        except (OSError, ValueError, Scapy_Exception) as exc:
            # Interface bị xoá giữa lúc __init__ và _open, hết file descriptor...
            raise SourceError(f"cannot capture on {self.iface}: {exc}") from exc
        finally:
            # Gỡ ngay: bộ lọc chỉ có nghĩa cho đúng lời gọi ở trên, cảnh báo
            # phát sinh sau đó (trong lúc đang bắt gói) vẫn phải hiện ra.
            log.removeFilter(_drop_link_layer_guess_warning)

    def frames(self):
        """Frame kế tiếp nhận được, cho tới khi bị dừng (REQ-1.1, 1.2).

        Không có điều kiện kết thúc: nguồn live chỉ dừng khi người dùng dừng
        (Ctrl+C hoặc SIGTERM -> main.py). Tín hiệu đến trong lúc đang chờ trong
        recv sẽ ném KeyboardInterrupt ngay tại `recv_raw` bên dưới; ngoại lệ đó
        đi xuyên qua generator này nên `with` dưới đây đóng socket, rồi Runner
        đóng sink trong finally của nó (REQ-1.6).
        """
        sock = self._open()
        with sock:
            while True:
                # recv_raw: bytes + nhãn thời gian, KHÔNG dissect (ADR-2).
                # Bytes này là những gì kernel giao, trừ một chỗ Scapy có sửa:
                # nếu frame có VLAN tag thì kernel tách tag ra ngoài dữ liệu và
                # Scapy chèn 4 byte tag trở lại đúng vị trí (offset 12) dựa vào
                # PACKET_AUXDATA -> tức là khôi phục bytes trên dây, không phải
                # dựng lại packet. Lab không có VLAN nên nhánh đó không chạy.
                _cls, data, ts = sock.recv_raw(_SNAPLEN)
                if not data:
                    # Socket trả về frame rỗng (hoặc một lớp socket khác lọc bỏ
                    # frame đi ra): không có byte nào để parse -> không sinh
                    # event, packet_id cũng không bị tiêu một số vô ích.
                    continue
                # ts là float giây (kernel cho nano giây qua SO_TIMESTAMPNS,
                # Scapy cộng thành float). Nhân trước rồi divmod: giữ đúng giao
                # ước 0 <= ts_usec < 1_000_000 của RawFrame mà không cần clamp,
                # và cắt xuống micro giây giống hệt luật của PCAP nano giây.
                # (Độ chính xác của float ở mốc thời gian hiện nay chỉ còn cỡ
                # 0.5 µs -> chữ số micro giây cuối có thể lệch 1 so với kernel.
                # Đây là giới hạn của chỗ Scapy trả float, không phải của ta;
                # T11.1 vì vậy so live với pcap sau khi bỏ trường timestamp.)
                ts_sec, ts_usec = divmod(int(ts * _USEC_PER_SEC), _USEC_PER_SEC)
                yield RawFrame(
                    data=data,
                    ts_sec=ts_sec,
                    ts_usec=ts_usec,
                    # Snaplen 65535 > MTU nên không có frame nào bị cắt. Scapy
                    # bỏ cờ MSG_TRUNC của recvmsg nên ta cũng không có cách nào
                    # phát hiện nếu điều đó xảy ra -> khai đúng những gì biết
                    # chắc: độ dài nhận được, và không tự nhận là cụt.
                    wire_len=len(data),
                    linktype=self.linktype,
                    source="live",
                )
