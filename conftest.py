"""Cấu hình chung cho pytest.

Đặt ở gốc repo vì hai lý do:
  1. pytest thêm thư mục chứa conftest.py vào sys.path, nhờ vậy `pytest` trần
     cũng import được package `idps` chứ không chỉ `python -m pytest` (lệnh
     -m tự thêm thư mục làm việc vào sys.path, nên trước đó chỉ nó chạy được).
  2. Chỗ đặt fixture dùng chung, để test module này không phải import test
     module kia.
"""
import pytest

# Chép tay từ design §5.4 — CỐ TÌNH không import từ idps.core.event, để test
# còn phát hiện được khi ai đó đổi thứ tự hay thêm/bớt khoá trong mã nguồn.
EVENT_KEYS = (
    "schema_version", "packet_id", "timestamp", "source", "cap_len", "wire_len",
    "linktype", "link_proto", "network_proto", "src_ip", "dst_ip",
    "transport_proto", "src_port", "dst_port", "app_proto", "detect_method",
    "status", "errors", "ethernet", "ipv4", "tcp", "udp", "app",
)


@pytest.fixture
def event_keys():
    """Tập khoá cấp cao bắt buộc của mọi event, đúng thứ tự (I-2)."""
    return EVENT_KEYS
