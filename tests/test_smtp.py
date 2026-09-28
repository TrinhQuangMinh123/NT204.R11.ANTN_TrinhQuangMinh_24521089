"""T9.1 — parser SMTP (REQ-9.1-9.3, Phụ lục A.7).

Payload trong file này viết thẳng dưới dạng bytes chứ không bắt từ lab, vì phần
lớn các ca cần kiểm là những thứ một server thật KHÔNG BAO GIỜ gửi: reply nhiều
dòng mang hai mã khác nhau, byte 8 bit trong một lệnh, dòng kết thúc bằng LF
trần. Bằng chứng trên traffic thật nằm ở TEST/TC-09 và TEST/TC-10.
"""
import random

import pytest

from idps.decode.smtp import (APP_FIELDS, COMMANDS, command_at_start,
                              parse_smtp, reply_code_at_start,
                              reply_shape_fits, stray_eol_offset)

# Reply chào của aiosmtpd trong lab (xem TEST/TC-10), dùng lại nhiều lần.
GREETING = b"220 victim.lab Python SMTP 1.4.6\r\n"
# Reply nhiều dòng của EHLO: hai dòng "-" rồi một dòng " " kết thúc (RFC 5321
# §4.2.1). Đây là ca REQ-9.3.
EHLO_REPLY = (b"250-victim.lab\r\n"
              b"250-SIZE 33554432\r\n"
              b"250 HELP\r\n")


# --- REQ-9.1: lệnh + tham số ------------------------------------------------

def test_ehlo():
    """Ca nền: tên lệnh và tham số tách đúng ở dấu cách (REQ-9.1)."""
    r = parse_smtp(b"EHLO attacker.lab\r\n")
    assert r.error is None
    assert r.fields == {
        "kind": "command",
        "command": "EHLO",
        "argument": "attacker.lab",
        "status_code": None,
        "lines": ["EHLO attacker.lab"],
    }


def test_helo():
    r = parse_smtp(b"HELO attacker.lab\r\n")
    assert (r.fields["command"], r.fields["argument"]) == ("HELO",
                                                           "attacker.lab")


def test_mail_from():
    """Tên lệnh CHỨA một dấu cách: split(" ") sẽ cho command="MAIL"."""
    r = parse_smtp(b"MAIL FROM:<attacker@attacker.lab>\r\n")
    assert r.error is None
    assert r.fields["command"] == "MAIL FROM"
    assert r.fields["argument"] == "<attacker@attacker.lab>"


def test_rcpt_to():
    r = parse_smtp(b"RCPT TO:<admin@victim.lab>\r\n")
    assert r.error is None
    assert r.fields["command"] == "RCPT TO"
    assert r.fields["argument"] == "<admin@victim.lab>"


def test_mail_from_with_space_after_the_colon():
    """RFC 5321 §4.1.2 không cho dấu cách ở đây, nhiều client vẫn gửi -> OWS."""
    r = parse_smtp(b"MAIL FROM: <a@b>\r\n")
    assert r.fields["argument"] == "<a@b>"


def test_lowercase_command():
    """RFC 5321 §2.4: lệnh không phân biệt hoa thường -> chuẩn hoá thành HOA."""
    r = parse_smtp(b"helo attacker.lab\r\n")
    assert r.error is None
    assert r.fields["command"] == "HELO"


@pytest.mark.parametrize("raw", [b"MaIl FrOm:<a@b>", b"mail from:<a@b>",
                                 b"MAIL FROM:<a@b>"])
def test_case_does_not_change_the_command_name(raw):
    assert parse_smtp(raw + b"\r\n").fields["command"] == "MAIL FROM"


def test_argument_keeps_its_own_case():
    """Chỉ TÊN LỆNH được chuẩn hoá; tham số là dữ liệu, giữ nguyên văn."""
    r = parse_smtp(b"MAIL FROM:<Attacker@Attacker.LAB>\r\n")
    assert r.fields["argument"] == "<Attacker@Attacker.LAB>"


@pytest.mark.parametrize("verb", [b"DATA", b"QUIT", b"RSET", b"NOOP"])
def test_commands_without_argument(verb):
    """Không có chỗ cho tham số -> argument là null, không phải chuỗi rỗng."""
    r = parse_smtp(verb + b"\r\n")
    assert r.error is None
    assert r.fields["command"] == verb.decode()
    assert r.fields["argument"] is None


def test_trailing_space_gives_an_empty_argument_not_null():
    """"Có chỗ nhưng bỏ trống" khác "không có chỗ" — hai tín hiệu khác nhau."""
    assert parse_smtp(b"HELO \r\n").fields["argument"] == ""
    assert parse_smtp(b"HELO\r\n").fields["argument"] is None


def test_auth_and_starttls():
    assert parse_smtp(b"AUTH LOGIN\r\n").fields["argument"] == "LOGIN"
    assert parse_smtp(b"STARTTLS\r\n").fields["command"] == "STARTTLS"


def test_every_command_of_appendix_c_is_recognised():
    """Danh sách lệnh là một tập ĐÓNG: 10 lệnh của Phụ lục C, không hơn."""
    assert len(COMMANDS) == 10
    for verb in COMMANDS:
        assert command_at_start(verb + b" x\r\n") is not None


def test_pipelined_commands_keep_every_line():
    """RFC 2920: nhiều lệnh trong một segment. command = lệnh ĐẦU (A2)."""
    r = parse_smtp(b"RSET\r\nQUIT\r\n")
    assert r.error is None
    assert r.fields["command"] == "RSET"
    assert r.fields["lines"] == ["RSET", "QUIT"]


# --- REQ-9.2: mã trả lời ----------------------------------------------------

def test_greeting_response():
    """Reply một dòng: status_code là SỐ, lines là phần text sau mã."""
    r = parse_smtp(GREETING)
    assert r.error is None
    assert r.fields == {
        "kind": "response",
        "command": None,
        "argument": None,
        "status_code": 220,
        "lines": ["victim.lab Python SMTP 1.4.6"],
    }


def test_status_code_is_an_int_not_a_string():
    """REQ-9.2 "dưới dạng số nguyên": luật phát hiện so khoảng (4xx, 5xx), mà
    so chuỗi thì "99" > "500"."""
    assert parse_smtp(b"550 no\r\n").fields["status_code"] == 550
    assert isinstance(parse_smtp(b"550 no\r\n").fields["status_code"], int)


def test_response_is_recognised_by_its_shape_not_by_the_port():
    """Parser không nhận tham số port: 4 byte đầu là tất cả căn cứ."""
    assert parse_smtp(b"421 too many\r\n").fields["kind"] == "response"


def test_reply_line_without_text():
    """RFC 5321 §4.2: phần "SP text" là TUỲ CHỌN -> "250" trần là hợp lệ."""
    r = parse_smtp(b"250-first\r\n250\r\n")
    assert r.error is None
    assert r.fields["lines"] == ["first", ""]


def test_unterminated_reply_keeps_the_code_but_no_lines():
    """Dòng chưa thấy CRLF bị bỏ khỏi `lines` (có thể đang bị cắt giữa), nhưng
    3 chữ số + dấu phân cách thì một vết cắt phía sau không đổi được."""
    r = parse_smtp(b"220 victim.lab Pyth")
    assert r.error is None
    assert r.fields["status_code"] == 220
    assert r.fields["lines"] == []


# --- REQ-9.3: reply nhiều dòng ----------------------------------------------

def test_multiline_reply_has_one_code_and_every_line():
    r = parse_smtp(EHLO_REPLY)
    assert r.error is None
    assert r.fields["status_code"] == 250
    assert r.fields["lines"] == ["victim.lab", "SIZE 33554432", "HELP"]


def test_multiline_reply_cut_across_segments_is_not_an_error():
    """Chỉ có dòng "-": reply còn tiếp ở segment sau. A2 không ghép luồng nên
    đây là dữ liệu chưa đủ, không phải dữ liệu sai."""
    r = parse_smtp(b"250-victim.lab\r\n250-SIZE 33554432\r\n")
    assert r.error is None
    assert r.fields["lines"] == ["victim.lab", "SIZE 33554432"]


def test_inconsistent_code_keeps_lines_and_reports_error():
    """RFC 5321 §4.2.1 buộc mọi dòng cùng mã -> khác mã là dữ liệu bất thường,
    giữ `lines` rồi báo lỗi (design §8.2)."""
    r = parse_smtp(b"250-ok so far\r\n550 denied\r\n")
    assert r.error is not None
    assert "550" in r.error and "250" in r.error
    assert r.fields["status_code"] == 250
    assert len(r.fields["lines"]) == 2


def test_a_non_reply_line_inside_a_reply_stops_and_keeps_the_rest():
    r = parse_smtp(b"250-ok\r\nGET / HTTP/1.1\r\n")
    assert r.error is not None and "not a reply line" in r.error
    assert r.fields["lines"] == ["ok"]


# --- ca lỗi: byte không phải ASCII ------------------------------------------

def test_non_ascii_byte_in_a_command():
    """RFC 5321 §2.3.1: lệnh là US-ASCII. Byte 8 bit -> lỗi có vị trí."""
    r = parse_smtp(b"MAIL FROM:<a@b\xff>\r\n")
    assert r.error is not None
    assert "0xff" in r.error and "ascii" in r.error
    assert r.fields["command"] == "MAIL FROM"      # vẫn biết lệnh gì


def test_non_ascii_byte_in_a_response_keeps_earlier_lines():
    r = parse_smtp(b"250-ok\r\n250 \xc3\r\n")
    assert r.error is not None and "0xc3" in r.error
    assert r.fields["lines"] == ["ok"]


# --- ca lỗi: CRLF lẻ (hình dạng SMTP smuggling, CVE-2023-51764) -------------

def test_bare_lf_in_a_command_is_reported():
    r = parse_smtp(b"EHLO attacker.lab\n")
    assert r.error is not None and "crlf" in r.error
    assert r.fields["command"] == "EHLO"
    # Dòng không kết thúc bằng CRLF -> không vào `lines`, và argument để null
    # thay vì ghi một giá trị có thể đã bị cắt.
    assert r.fields["lines"] == [] and r.fields["argument"] is None


def test_bare_lf_after_a_complete_line_is_reported():
    r = parse_smtp(b"250-ok\r\n250 done\n")
    assert r.error is not None and "crlf" in r.error
    assert r.fields["lines"] == ["ok"]


def test_bare_cr_is_reported():
    r = parse_smtp(b"QUIT\r")
    assert r.error is not None and "crlf" in r.error


def test_stray_eol_offset_points_at_the_offending_byte():
    assert stray_eol_offset(b"EHLO a\r\n") is None
    assert stray_eol_offset(b"EHLO a\n") == 6
    assert stray_eol_offset(b"\nEHLO a\r\n") == 0
    assert stray_eol_offset(b"EHLO a\r") == 6
    assert stray_eol_offset(b"250-a\r\n250 b\n") == 12


def test_parse_error_wins_over_the_crlf_error():
    """Hai lỗi cùng lúc: lý do chỉ đúng vào TRƯỜNG không tin được được ưu tiên,
    vì `ParseResult.error` chỉ chứa một chuỗi."""
    r = parse_smtp(b"250-ok\r\n550 denied\r\n\n")
    assert "declares code 550" in r.error


def test_a_line_ending_in_bare_lf_is_not_parsed_as_a_line_at_all():
    """Hệ quả của hai luật đứng cạnh nhau: dòng thiếu CRLF không vào `lines`,
    nên mã 550 của nó cũng KHÔNG được đem so với mã dòng đầu — lỗi duy nhất báo
    ra là lỗi CRLF. Nói cách khác: LF trần làm mất khả năng kiểm tra phần sau
    nó, và đó chính là điều kẻ tấn công muốn (CVE-2023-51764)."""
    r = parse_smtp(b"250-ok\r\n550 denied\n")
    assert r.fields["lines"] == ["ok"]
    assert "crlf" in r.error and "550" not in r.error


# --- T9.2b: chữ ký reply là probing parser (Phụ lục C v8, R5) ---------------

@pytest.mark.parametrize("payload", [
    GREETING,                                   # một dòng
    EHLO_REPLY,                                 # nhiều dòng, cùng mã
    b"250-first\r\n250\r\n",                    # dòng không có text (RFC 5321 §4.2)
    b"250 OK\r\n250 OK\r\n550 no such user\r\n",  # reply gộp, RFC 2920
    b"250 ok\xff\r\n",                          # byte lạ trong text -> parser lo
])
def test_reply_shape_accepts_real_replies(payload):
    assert reply_shape_fits(payload) is True


@pytest.mark.parametrize("payload", [
    b"404 page not found\r\n<hr>nginx\r\n",     # mảnh body HTTP giữa luồng
    b"502 Bad Gateway\r\n<html><body>\r\n",
    b"123 Main Street, Apt 4\r\nHo Chi Minh City\r\n",
    b"200 OK duoc ghi trong log\r\nline hai khong phai reply\r\n",
    b"250 ban ghi da luu",                      # không có CRLF nào -> chưa trọn dòng
    b"250 ok\r\n\r\n",                          # dòng trống không phải reply line
])
def test_reply_shape_rejects_text_that_only_starts_like_a_reply(payload):
    """Điểm cốt lõi của T9.2b: dòng THỨ HAI là thứ tố giác. Chữ ký cũ chỉ xem 4
    byte đầu nên nhận hết các payload này (đo được 49,9% nhận nhầm trên văn bản
    ngẫu nhiên, còn 27,0% sau khi siết)."""
    assert reply_shape_fits(payload) is False


def test_a_single_line_is_the_residual_risk_r5():
    """Ca KHÔNG chữ ký không-trạng-thái nào phân biệt được: một dòng đơn đúng là
    một reply hợp lệ về cú pháp. Cần bảng flow (ngoài A2) — ghi lại để biết đây
    là giới hạn đã lường, không phải bug."""
    assert reply_shape_fits(b"404 page not found\r\n") is True


def test_the_signature_is_lenient_about_bytes_but_the_parser_is_not():
    """Chia việc: chữ ký xét HÌNH DẠNG (byte lạ vẫn khớp, nhờ latin-1), parser
    xét NỘI DUNG (ascii nghiêm ngặt, và báo lỗi). Nếu chữ ký cũng nghiêm ngặt thì
    event ra UNKNOWN và lỗi này không bao giờ được báo."""
    payload = b"250 ok\xff\r\n"
    assert reply_shape_fits(payload) is True
    assert "0xff" in parse_smtp(payload).error


def test_inconsistent_codes_stay_a_parser_error_not_a_signature_miss():
    """RFC 5321 §4.2.1 buộc mọi dòng của MỘT reply cùng mã, nhưng RFC 2920 cho
    server gộp nhiều reply vào một segment → "cùng mã" không phải bất biến của
    một segment, nên nó KHÔNG nằm trong chữ ký (design ADR-5)."""
    payload = b"250-ok so far\r\n550 denied\r\n"
    assert reply_shape_fits(payload) is True                   # vẫn nhận là SMTP
    assert "declares code 550" in parse_smtp(payload).error     # rồi mới báo lỗi


# --- chữ ký (dùng bởi detector ở T9.2) --------------------------------------

def test_command_signature_needs_a_delimiter():
    """Cùng lý lẽ với dấu cách sau method của HTTP: "EHLOX" không phải lệnh."""
    assert command_at_start(b"EHLO ") == "EHLO"
    assert command_at_start(b"EHLO\r\n") == "EHLO"
    assert command_at_start(b"EHLO") == "EHLO"     # segment cắt ngay sau lệnh
    assert command_at_start(b"EHLOX") is None
    assert command_at_start(b"DATABASE\r\n") is None


def test_tab_is_not_a_delimiter():
    """RFC 5321 §4.1.1 chỉ cho SP; dễ tính hơn RFC là tự tạo cách đọc thứ hai."""
    assert command_at_start(b"EHLO\ta\r\n") is None


def test_reply_signature_needs_exactly_three_digits_and_a_separator():
    assert reply_code_at_start(b"220 ok") == 220
    assert reply_code_at_start(b"250-ok") == 250
    assert reply_code_at_start(b"999 odd") == 999      # Phụ lục C: "3 chữ số"
    assert reply_code_at_start(b"2500 ok") is None     # 4 chữ số
    assert reply_code_at_start(b"25 ok") is None
    assert reply_code_at_start(b"220") is None         # thiếu dấu phân cách
    assert reply_code_at_start(b"220ok") is None
    assert reply_code_at_start(b"") is None


def test_a_payload_that_is_neither_shape_is_an_error_not_a_crash():
    """Qua pipeline ca này không xảy ra (detector gác trước), nhưng parser phải
    trả lời trung thực khi bị gọi trực tiếp."""
    r = parse_smtp(b"\x16\x03\x01\x02\x00")
    assert r.error is not None and "neither" in r.error
    assert r.fields["kind"] == "command" and r.fields["command"] is None


# --- I-2 / I-1: tập khoá và tính không-ném ----------------------------------

@pytest.mark.parametrize("payload", [
    GREETING, EHLO_REPLY, b"EHLO a\r\n", b"QUIT\r\n",
    b"250-ok\r\n550 no\r\n",          # có lỗi mã
    b"MAIL FROM:<a@b\xff>\r\n",       # có lỗi decode
    b"EHLO a\n",                      # có lỗi CRLF
    b"", b"\x00\x01",                 # rác
])
def test_field_keys_match_appendix_a7(payload):
    """Đủ 5 khoá, đúng thứ tự, KỂ CẢ khi có lỗi (I-2, design §5.4)."""
    fields = parse_smtp(payload).fields
    assert tuple(fields) == APP_FIELDS


@pytest.mark.parametrize("payload", [GREETING, b"EHLO a\r\n", b"250\r\n"])
def test_kind_is_always_one_of_two_values(payload):
    assert parse_smtp(payload).fields["kind"] in ("command", "response")


def test_random_payloads_never_raise():
    """I-1: dữ liệu do kẻ tấn công cung cấp không được ném ngoại lệ."""
    rng = random.Random(20260927)
    for _ in range(500):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        result = parse_smtp(payload)
        assert tuple(result.fields) == APP_FIELDS
        assert result.error is None or isinstance(result.error, str)


def test_smtp_like_random_payloads_never_raise():
    """Rác ngẫu nhiên gần như không bao giờ khớp chữ ký -> tự sinh payload có
    hình dạng SMTP để các nhánh parse thật sự được chạy."""
    rng = random.Random(24521089)
    pieces = [b"250", b"220", b"550", b" ", b"-", b"\r\n", b"\n", b"\r",
              b"EHLO", b"MAIL FROM:", b"QUIT", b"a@b", b"\xff", b"", b"   "]
    for _ in range(500):
        payload = b"".join(rng.choice(pieces)
                           for _ in range(rng.randrange(0, 10)))
        result = parse_smtp(payload)
        assert tuple(result.fields) == APP_FIELDS
        assert isinstance(result.fields["lines"], list)


def test_same_input_gives_same_result():
    """NFR-2: không có dict/set nào ảnh hưởng kết quả."""
    results = [parse_smtp(EHLO_REPLY).fields for _ in range(5)]
    assert results[1:] == results[:-1]
