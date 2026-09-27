"""Khung event chuẩn hoá — hợp đồng giữa decode và mọi module phía sau (§5.4).

File này nằm trong core/ nên KHÔNG được import idps.decode hay idps.output
(I-9): các bài sau đọc lại events.jsonl bằng đúng module này mà không phải kéo
theo cả bộ parser.
"""
import base64
from datetime import datetime, timedelta, timezone

# Tăng khi một khoá bị đổi tên, đổi kiểu hoặc bị xoá (REQ-12.6). Module bài sau
# đọc khoá này trước để biết mình có hiểu được dòng JSON hay không.
SCHEMA_VERSION = 1

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_USEC_PER_SEC = 1_000_000

# Ba tầng mà giá trị "UNKNOWN" làm packet được đếm là unknown (REQ-13.5).
# app_proto CỐ TÌNH không có trong danh sách: payload lạ trên một packet TCP
# hợp lệ vẫn là một packet đã parse xong, không phải packet không hiểu được.
_UNKNOWN_KEYS = ("link_proto", "network_proto", "transport_proto")


def format_timestamp(ts_sec: int, ts_usec: int) -> str:
    """Hai số nguyên -> "1970-01-01T00:00:00.000005Z" (ADR-7).

    Không đi qua float ở bất kỳ bước nào: phần giây dựng bằng timedelta (số
    học số nguyên), phần micro giây in thẳng bằng {:06d}. Đưa qua float sẽ
    làm mất micro giây với timestamp cỡ 1.79e9 giây của hiện tại.

    ts_usec của một bản ghi PCAP là uint32 đọc thẳng từ file, tức do người tạo
    file quyết định — 4_000_000 là giá trị hợp lệ về mặt cú pháp. divmod dồn
    phần thừa sang giây để chuỗi luôn đúng 6 chữ số micro giây, giữ nguyên
    tính chất "so sánh chuỗi bằng < ra đúng thứ tự thời gian".
    """
    sec, usec = divmod(ts_sec * _USEC_PER_SEC + ts_usec, _USEC_PER_SEC)
    moment = _EPOCH + timedelta(seconds=sec)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{usec:06d}Z"


def b64(data: bytes) -> str:
    """Bytes -> base64 chuẩn RFC 4648 (C-13). b"" -> "".

    JSON không có kiểu nhị phân. data.decode() không dùng được vì payload thật
    chứa byte không hợp lệ trong UTF-8; dùng errors="replace" thì I-4 (giải mã
    ngược ra đúng bytes gốc) không còn đúng.
    """
    return base64.b64encode(data).decode("ascii")


def new_event(frame, packet_id: int) -> dict:
    """Khung event đủ khoá, đúng thứ tự §5.4 — các tầng chỉ ĐIỀN, không THÊM.

    Dựng đủ khoá ngay từ đầu là cách bảo đảm I-2: một packet dừng ở tầng link
    và một packet đi hết tới HTTP vẫn ra cùng tập khoá, nên module phía sau
    đọc e["tcp"] được mà không cần .get(). dict của Python giữ thứ tự chèn,
    nên thứ tự khoá trong file JSON chính là thứ tự viết dưới đây (NFR-2).
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "packet_id": packet_id,
        "timestamp": format_timestamp(frame.ts_sec, frame.ts_usec),
        "source": frame.source,
        # cap_len = số byte THỰC SỰ có trong file/buffer; wire_len = độ dài gốc
        # trên dây. Hai số này khác nhau khi capture bị cắt theo snaplen.
        "cap_len": len(frame.data),
        "wire_len": frame.wire_len,
        "linktype": frame.linktype,
        "link_proto": None,
        "network_proto": None,
        "src_ip": None,
        "dst_ip": None,
        "transport_proto": None,
        "src_port": None,
        "dst_port": None,
        "app_proto": None,
        "detect_method": None,
        "status": "ok",
        "errors": [],
        "ethernet": None,
        "ipv4": None,
        "tcp": None,
        "udp": None,
        "app": None,
    }


def add_error(event: dict, layer: str, reason: str) -> None:
    """Ghi một lỗi kèm TÊN TẦNG phát hiện ra nó (REQ-15.2).

    Một packet có thể mang nhiều lỗi (vd bản ghi bị cắt + IPv4 hỏng), nên đây
    là list chứ không phải một trường đơn.
    """
    event["errors"].append({"layer": layer, "reason": reason})


def compute_status(event: dict) -> str:
    """malformed > unknown > ok (§5.4).

    malformed thắng vì nó nói về tính toàn vẹn của dữ liệu ("byte không khớp
    với header"), còn unknown chỉ nói về phạm vi hỗ trợ của chương trình
    ("giao thức này bài 1 chưa parse"). Một packet vừa hỏng vừa lạ thì cái
    đáng báo là nó hỏng.
    """
    if event["errors"]:
        return "malformed"
    if any(event[key] == "UNKNOWN" for key in _UNKNOWN_KEYS):
        return "unknown"
    return "ok"
