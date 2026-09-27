"""T8.1 — parser DNS (REQ-8.1–8.5, Phụ lục A.6, I-6).

Mọi message trong file này được dựng bằng `struct`/hex thay vì bắt từ lab: chỉ
cách đó mới tạo được các ca mà một server thật không bao giờ gửi (con trỏ vòng
lặp, ANCOUNT sai, nhãn có loại reserved) — mà đó chính là các ca REQ-8.4/8.5
nhắm tới. Bằng chứng trên traffic thật nằm ở TEST/TC-07 và TEST/TC-08.
"""
import base64
import struct
import time

import pytest

from idps.decode.dns import (DNS_HEADER_LEN, MAX_NAME_LEN, parse_dns,
                             question_section_fits)

# --- tiện ích dựng message --------------------------------------------------

def header(ident=0x1234, flags=0x0100, qdcount=1, ancount=0,
           nscount=0, arcount=0):
    return struct.pack("!HHHHHH", ident, flags, qdcount, ancount,
                       nscount, arcount)


def name(*labels):
    """("victim", "lab") -> b"\\x06victim\\x03lab\\x00" (tên không nén)."""
    out = b""
    for label in labels:
        raw = label if isinstance(label, bytes) else label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def question(qname=None, qtype=1, qclass=1):
    if qname is None:
        qname = name("victim", "lab")
    return qname + struct.pack("!HH", qtype, qclass)


def answer(qname=None, rtype=1, rclass=1, ttl=300, rdata=None, rdlength=None):
    """rdlength=None -> khai đúng độ dài thật của rdata."""
    if qname is None:
        qname = b"\xc0\x0c"                 # con trỏ về question (offset 12)
    if rdata is None:
        rdata = bytes([10, 20, 0, 10])      # 10.20.0.10
    if rdlength is None:
        rdlength = len(rdata)
    return qname + struct.pack("!HHIH", rtype, rclass, ttl, rdlength) + rdata


# --- REQ-8.1: query --------------------------------------------------------

def test_query_a():
    """Query A: transaction ID, tên miền, query type (REQ-8.1)."""
    r = parse_dns(header() + question())
    assert r.error is None
    assert r.fields == {
        "id": 0x1234,
        "qr": "query",
        "opcode": "QUERY",
        "rcode": "NOERROR",
        "qdcount": 1,
        "ancount": 0,
        "questions": [{"name": "victim.lab", "type": "A"}],
        "answers": [],
    }


def test_field_keys_match_appendix_a6():
    """Tập khoá và thứ tự khoá đúng design §5.4, kể cả trên message hỏng (I-2)."""
    expected = ("id", "qr", "opcode", "rcode", "qdcount", "ancount",
                "questions", "answers")
    assert tuple(parse_dns(header() + question()).fields) == expected
    assert tuple(parse_dns(b"").fields) == expected


def test_qr_bit_and_rcode():
    """Một bit QR quyết định query/response; 4 bit thấp là rcode."""
    assert parse_dns(header(flags=0x0100) + question()).fields["qr"] == "query"
    resp = parse_dns(header(flags=0x8180, ancount=0) + question())
    assert resp.fields["qr"] == "response"
    assert resp.fields["rcode"] == "NOERROR"
    # REFUSED: dnsmasq trả mã này cho tên ngoài zone (thấy ở T1.5)
    refused = parse_dns(header(flags=0x8185) + question())
    assert refused.fields["rcode"] == "REFUSED"
    nx = parse_dns(header(flags=0x8183) + question())
    assert nx.fields["rcode"] == "NXDOMAIN"


def test_unknown_numbers_keep_their_value():
    """Type/rcode/opcode lạ -> chuỗi có con số, không mất thông tin."""
    # opcode 3 chưa được gán nghĩa (RFC 6895), rcode 15 cũng vậy
    r = parse_dns(header(flags=0x980F) + question(qtype=65))
    assert r.fields["questions"][0]["type"] == "TYPE65"
    assert r.fields["rcode"] == "RCODE15"
    assert r.fields["opcode"] == "OPCODE3"


def test_root_name():
    """Tên chỉ có nhãn gốc -> "." (vd query cho root NS)."""
    r = parse_dns(header() + question(qname=b"\x00", qtype=2))
    assert r.error is None
    assert r.fields["questions"] == [{"name": ".", "type": "NS"}]


# --- REQ-8.2, 8.3: response có answer + tên nén ----------------------------

def test_response_with_a_answer_and_compressed_name():
    """Answer A: name (giải từ con trỏ 0xC00C), type, ttl, data dạng chấm."""
    message = header(flags=0x8180, ancount=1) + question() + answer()
    assert message[DNS_HEADER_LEN + len(question()):][:2] == b"\xc0\x0c"
    r = parse_dns(message)
    assert r.error is None
    assert r.fields["qr"] == "response"
    assert r.fields["answers"] == [
        {"name": "victim.lab", "type": "A", "ttl": 300, "data": "10.20.0.10"},
    ]


def test_pointer_resolves_to_the_same_bytes_as_a_full_name():
    """Cùng một tên, viết nén và viết đầy đủ -> cùng một chuỗi (REQ-8.3)."""
    compressed = parse_dns(header(flags=0x8180, ancount=1) + question()
                           + answer(qname=b"\xc0\x0c"))
    spelled = parse_dns(header(flags=0x8180, ancount=1) + question()
                        + answer(qname=name("victim", "lab")))
    assert compressed.fields["answers"] == spelled.fields["answers"]


def test_pointer_to_a_middle_label():
    """Con trỏ trỏ vào GIỮA tên -> chỉ lấy phần đuôi ("lab").

    Offset 12 là nhãn "victim"; 12 + 1 + 6 = 19 là nhãn "lab".
    """
    r = parse_dns(header(flags=0x8180, ancount=1) + question()
                  + answer(qname=b"\xc0\x13"))
    assert r.error is None
    assert r.fields["answers"][0]["name"] == "lab"


def test_cname_rdata_is_a_name_and_may_be_compressed():
    """RDATA của CNAME là một tên, cũng được nén (NAME_RDATA_TYPES)."""
    r = parse_dns(header(flags=0x8180, ancount=1) + question()
                  + answer(rtype=5, rdata=b"\xc0\x0c"))
    assert r.error is None
    assert r.fields["answers"][0] == {"name": "victim.lab", "type": "CNAME",
                                      "ttl": 300, "data": "victim.lab"}


def test_aaaa_is_eight_hex_groups():
    rdata = bytes.fromhex("fd00" "0000" "0000" "0000" "0000" "0000" "0000" "0001")
    r = parse_dns(header(flags=0x8180, ancount=1) + question(qtype=28)
                  + answer(rtype=28, rdata=rdata))
    assert r.error is None
    assert r.fields["answers"][0]["data"] == "fd00:0000:0000:0000:0000:0000:0000:0001"


def test_unknown_rdata_keeps_bytes_as_base64():
    """Type chưa hỗ trợ -> giữ nguyên bytes (I-4), không bỏ bản ghi."""
    rdata = bytes.fromhex("00112233445566")
    r = parse_dns(header(flags=0x8180, ancount=1) + question(qtype=99)
                  + answer(rtype=99, rdata=rdata))
    assert r.error is None
    got = r.fields["answers"][0]["data"]
    assert base64.b64decode(got) == rdata


def test_two_answers():
    message = (header(flags=0x8180, ancount=2) + question()
               + answer(rdata=bytes([10, 20, 0, 10]))
               + answer(rdata=bytes([10, 20, 0, 11]), ttl=60))
    r = parse_dns(message)
    assert r.error is None
    assert [a["data"] for a in r.fields["answers"]] == ["10.20.0.10", "10.20.0.11"]
    assert [a["ttl"] for a in r.fields["answers"]] == [300, 60]


# --- REQ-8.4: con trỏ độc hại ----------------------------------------------

def test_pointer_loop():
    """Con trỏ tự trỏ vào chính nó -> lỗi, KHÔNG treo (REQ-8.4, I-6).

    Message: question bình thường, rồi answer có tên = con trỏ trỏ vào đúng vị
    trí của chính con trỏ đó (offset 28).
    """
    prefix = header(flags=0x8180, ancount=1) + question()
    assert len(prefix) == 28
    start = time.monotonic()
    r = parse_dns(prefix + struct.pack("!H", 0xC000 | 28) + b"\x00\x01")
    elapsed = time.monotonic() - start
    assert elapsed < 1.0                       # điều kiện dừng của T8.1
    assert r.error is not None and "loop" in r.error
    assert "internal" not in r.error


def test_pointer_loop_between_two_pointers():
    """Hai con trỏ trỏ vòng cho nhau — bộ đếm N lần nhảy sẽ bỏ sót ca này."""
    # offset 12: con trỏ -> 14 ; offset 14: con trỏ -> 12
    message = (header() + struct.pack("!H", 0xC000 | 14)
               + struct.pack("!H", 0xC000 | 12) + b"\x00\x01\x00\x01")
    r = parse_dns(message)
    assert r.error is not None and "loop" in r.error


def test_pointer_out_of_range():
    """Con trỏ trỏ ra ngoài payload -> lỗi, không đọc bừa (REQ-8.4)."""
    r = parse_dns(header() + struct.pack("!H", 0xC000 | 9999) + b"\x00\x01")
    assert r.error is not None
    assert "outside" in r.error and "9999" in r.error


def test_every_pointer_target_past_the_end_is_rejected():
    """Quét mọi offset ngoài phạm vi: không ca nào lọt và không ca nào ném."""
    for target in range(1, 40):
        message = header() + struct.pack("!H", 0xC000 | target) + b"\x00\x01"
        r = parse_dns(message)
        if target >= len(message):
            assert r.error is not None, target
        # target < len(message): hoặc parse được, hoặc lỗi — miễn không ném


def test_label_longer_than_63_bytes():
    """Byte độ dài 100 (0b01100100) -> loại nhãn reserved, không phải nhãn dài."""
    r = parse_dns(header() + bytes([100]) + b"A" * 100 + b"\x00\x00\x01\x00\x01")
    assert r.error is not None
    assert "reserved" in r.error


def test_reserved_label_type_10():
    r = parse_dns(header() + bytes([0x80]) + b"\x00\x00\x01\x00\x01")
    assert r.error is not None and "reserved" in r.error


def test_name_longer_than_255_bytes():
    """Nhiều nhãn hợp lệ nhưng tổng quá 255 -> lỗi (RFC 1035 §2.3.4)."""
    labels = [b"a" * 63] * 5                   # 5*64 = 320 > 255
    r = parse_dns(header() + name(*labels) + b"\x00\x01\x00\x01")
    assert r.error is not None
    assert str(MAX_NAME_LEN) in r.error


def test_truncated_name_at_end_of_payload():
    """Nhãn khai 6 byte nhưng payload hết -> lỗi, không slice im lặng (I-5)."""
    r = parse_dns(header() + b"\x06vic")
    assert r.error is not None
    assert "6 bytes" in r.error


def test_binary_label_is_escaped_not_rejected():
    """Nhãn chứa byte lạ là dữ liệu hợp lệ (RFC 1035 §3.1) — dấu hiệu tunneling."""
    r = parse_dns(header() + question(qname=name(b"a\xffb", "lab")))
    assert r.error is None
    assert r.fields["questions"][0]["name"] == "a\\xffb.lab"


# --- REQ-8.5: số đếm khai sai ----------------------------------------------

def test_ancount_larger_than_actual_keeps_parsed_answers():
    """ANCOUNT=5 nhưng chỉ có 1 answer -> giữ 1 answer + lỗi (REQ-8.5)."""
    r = parse_dns(header(flags=0x8180, ancount=5) + question() + answer())
    assert r.error is not None
    assert r.fields["ancount"] == 5                  # con số bên gửi khai
    assert len(r.fields["answers"]) == 1             # bản ghi thật đã đọc được
    assert r.fields["answers"][0]["data"] == "10.20.0.10"
    assert "2/5" in r.error                          # lỗi ở bản ghi thứ hai


def test_qdcount_larger_than_actual_keeps_parsed_questions():
    r = parse_dns(header(qdcount=3) + question())
    assert r.error is not None
    assert r.fields["qdcount"] == 3
    assert len(r.fields["questions"]) == 1
    assert "2/3" in r.error


def test_rdlength_longer_than_payload():
    """RDATA tự khai độ dài -> phải kiểm trước khi cắt; vẫn giữ name/type/ttl."""
    r = parse_dns(header(flags=0x8180, ancount=1) + question()
                  + answer(rdlength=50))
    assert r.error is not None and "rdata" in r.error
    assert r.fields["answers"][0]["name"] == "victim.lab"
    assert r.fields["answers"][0]["ttl"] == 300
    assert r.fields["answers"][0]["data"] is None


def test_a_record_with_wrong_rdlength():
    """Type A nhưng rdata 5 byte -> lỗi, bytes vẫn giữ lại dạng base64."""
    r = parse_dns(header(flags=0x8180, ancount=1) + question()
                  + answer(rdata=b"\x0a\x14\x00\x0a\x00"))
    assert r.error is not None and "expected 4" in r.error
    assert base64.b64decode(r.fields["answers"][0]["data"]) == b"\x0a\x14\x00\x0a\x00"


def test_header_too_short():
    for length in range(DNS_HEADER_LEN):
        r = parse_dns(b"\x00" * length)
        assert r.error is not None and "header" in r.error
        assert r.fields["questions"] == [] and r.fields["answers"] == []


def test_never_raises_on_random_payloads():
    """Lưới cuối: 500 payload ngẫu nhiên có seed cố định, không ca nào ném."""
    import random
    rng = random.Random(20260927)
    for _ in range(500):
        payload = bytes(rng.randrange(256)
                        for _ in range(rng.randrange(0, 60)))
        parse_dns(payload)                     # chỉ cần không ném


# --- chữ ký nhận diện (Phụ lục C) — dùng ở T8.2 ----------------------------

def test_question_section_fits():
    assert question_section_fits(header() + question()) is True


@pytest.mark.parametrize("payload, reason", [
    (b"", "rỗng"),
    (b"\x00" * 11, "ngắn hơn 12 byte"),
    (header(qdcount=0), "qdcount = 0"),
    (header() + b"\x06vic", "question bị cắt"),
    (header() + struct.pack("!H", 0xC000 | 12) + b"\x00\x01", "con trỏ vòng lặp"),
])
def test_question_section_does_not_fit(payload, reason):
    assert question_section_fits(payload) is False, reason
