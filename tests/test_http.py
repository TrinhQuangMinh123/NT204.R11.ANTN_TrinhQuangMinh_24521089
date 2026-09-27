"""T6.3 — parser HTTP/1.x (REQ-7.1-7.5, Phụ lục A.5, I-4)."""
import base64

import pytest

from idps.decode.http import APP_FIELDS, parse_http

# Request thật do curl 8.14.1 gửi trong lab (xem packet 4 của lab_mixed.pcap).
CURL_GET = (
    b"GET / HTTP/1.1\r\n"
    b"Host: 10.20.0.10\r\n"
    b"User-Agent: curl/8.14.1\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)
NGINX_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 12\r\n"
    b"\r\n"
    b"hello lab\r\n\r\n"
)


# --- khung `app` (Phụ lục A.5, I-2) -----------------------------------------

@pytest.mark.parametrize("payload", [CURL_GET, NGINX_200, b"GET /", b"HTTP/1."])
def test_every_result_has_the_same_keys_in_order(payload):
    """Request, response, mảnh cụt: cùng một tập khoá, đúng thứ tự §5.4."""
    assert tuple(parse_http(payload).fields) == APP_FIELDS


def test_request_leaves_the_response_only_fields_null():
    fields = parse_http(CURL_GET).fields
    assert fields["status_code"] is None and fields["reason"] is None


def test_response_leaves_the_request_only_fields_null():
    fields = parse_http(NGINX_200).fields
    assert fields["method"] is None and fields["uri"] is None


# --- REQ-7.1: request line + header ----------------------------------------

def test_get_request():
    result = parse_http(CURL_GET)
    assert result.error is None
    assert result.fields["kind"] == "request"
    assert result.fields["method"] == "GET"
    assert result.fields["uri"] == "/"
    assert result.fields["version"] == "HTTP/1.1"
    assert result.fields["incomplete"] is False
    assert result.payload == b""            # HTTP là tầng trên cùng của bài 1


def test_headers_keep_their_order():
    assert parse_http(CURL_GET).fields["headers"] == [
        ["Host", "10.20.0.10"],
        ["User-Agent", "curl/8.14.1"],
        ["Accept", "*/*"],
    ]


def test_duplicate_header_names_are_all_kept():
    """Hai Content-Length khác nhau là tín hiệu tấn công — dict sẽ ghi đè."""
    payload = (b"POST / HTTP/1.1\r\nContent-Length: 5\r\n"
               b"Content-Length: 99\r\nX-A: 1\r\nX-A: 2\r\n\r\nabcde")
    assert parse_http(payload).fields["headers"] == [
        ["Content-Length", "5"], ["Content-Length", "99"],
        ["X-A", "1"], ["X-A", "2"],
    ]


def test_query_string_stays_in_the_uri():
    payload = b"GET /a.php?id=1%27%20OR%201=1 HTTP/1.1\r\nHost: x\r\n\r\n"
    assert parse_http(payload).fields["uri"] == "/a.php?id=1%27%20OR%201=1"


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "HEAD",
                                    "OPTIONS"])
def test_all_six_methods(method):
    payload = f"{method} / HTTP/1.1\r\nHost: x\r\n\r\n".encode()
    assert parse_http(payload).fields["method"] == method


def test_request_with_no_header_at_all():
    result = parse_http(b"GET / HTTP/1.1\r\n\r\n")
    assert result.error is None
    assert result.fields["headers"] == []
    assert result.fields["incomplete"] is False


# --- giá trị bị cắt OWS, tên giữ nguyên văn ---------------------------------

def test_header_value_is_stripped_of_optional_whitespace():
    """RFC 9112 §5: OWS quanh giá trị không phải dữ liệu."""
    payload = b"GET / HTTP/1.1\r\nHost:  \t10.20.0.10 \t\r\n\r\n"
    assert parse_http(payload).fields["headers"] == [["Host", "10.20.0.10"]]


def test_header_value_may_contain_a_colon():
    """partition() cắt ở dấu ":" ĐẦU TIÊN, nên URL trong giá trị còn nguyên."""
    payload = b"GET / HTTP/1.1\r\nReferer: http://a/b:c\r\n\r\n"
    assert parse_http(payload).fields["headers"] == [
        ["Referer", "http://a/b:c"]]


def test_empty_header_value_is_kept():
    payload = b"GET / HTTP/1.1\r\nX-Empty:\r\n\r\n"
    assert parse_http(payload).fields["headers"] == [["X-Empty", ""]]


# --- REQ-7.2: body ----------------------------------------------------------

def test_post_with_body():
    payload = (b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n"
               b"\r\nuser=admin&")
    result = parse_http(payload)
    assert result.error is None
    assert result.fields["method"] == "POST"
    assert result.fields["uri"] == "/submit"
    assert result.fields["body_len"] == 11
    assert base64.b64decode(result.fields["body_b64"]) == b"user=admin&"


def test_body_len_counts_bytes_present_not_content_length():
    """REQ-7.2 "phần body CÓ TRONG packet": body trải qua nhiều segment."""
    payload = b"POST / HTTP/1.1\r\nContent-Length: 1000\r\n\r\nabc"
    fields = parse_http(payload).fields
    assert fields["body_len"] == 3                 # không phải 1000
    assert ["Content-Length", "1000"] in fields["headers"]
    assert parse_http(payload).error is None       # lệch không phải lỗi parse


def test_body_may_contain_the_blank_line_again():
    """find() lấy dòng trống ĐẦU TIÊN, nên CRLFCRLF trong body không cắt sai."""
    payload = b"POST / HTTP/1.1\r\nX: 1\r\n\r\nhead\r\n\r\ntail"
    assert parse_http(payload).fields["body_len"] == len(b"head\r\n\r\ntail")


def test_empty_body_gives_zero_and_empty_string():
    fields = parse_http(b"GET / HTTP/1.1\r\nX: 1\r\n\r\n").fields
    assert fields["body_len"] == 0 and fields["body_b64"] == ""


@pytest.mark.parametrize("body", [
    b"",
    b"user=admin&pass=1234",
    bytes(range(256)),                  # body nhị phân: file tải lên
    b"\x00" * 64,
    "tiếng Việt".encode("utf-8"),
    b"--boundary\r\nContent-Type: x\r\n\r\n\x89PNG\r\n",
])
def test_body_roundtrip(body):
    """I-4: base64 giải mã ngược ra ĐÚNG bytes gốc, kể cả byte không phải ASCII.

    Byte lạ trong BODY không phải lỗi (chỉ phần header buộc ASCII — REQ-7.5):
    một file ảnh tải lên qua POST là body nhị phân hoàn toàn hợp lệ.
    """
    payload = b"POST /u HTTP/1.1\r\nX: 1\r\n\r\n" + body
    result = parse_http(payload)
    assert result.error is None
    assert base64.b64decode(result.fields["body_b64"]) == body
    assert result.fields["body_len"] == len(body)


# --- REQ-7.3: response ------------------------------------------------------

def test_response_status_line():
    result = parse_http(NGINX_200)
    assert result.error is None
    assert result.fields["kind"] == "response"
    assert result.fields["version"] == "HTTP/1.1"
    assert result.fields["status_code"] == 200
    assert result.fields["reason"] == "OK"


def test_status_code_is_an_int_not_a_string():
    """Luật phát hiện so sánh khoảng (4xx/5xx); chuỗi thì "99" > "500"."""
    code = parse_http(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"
                      ).fields["status_code"]
    assert code == 503 and isinstance(code, int) and not isinstance(code, str)


def test_reason_phrase_may_contain_spaces():
    fields = parse_http(b"HTTP/1.1 404 Not Found\r\n\r\n").fields
    assert fields["status_code"] == 404 and fields["reason"] == "Not Found"


def test_empty_reason_phrase_is_not_an_error():
    """RFC 9112 §4 cho phép reason rỗng: "" khác null (null = đây là request)."""
    result = parse_http(b"HTTP/1.1 204 \r\n\r\n")
    assert result.error is None and result.fields["reason"] == ""


def test_missing_reason_phrase_is_not_an_error():
    result = parse_http(b"HTTP/1.1 204\r\n\r\n")
    assert result.error is None
    assert result.fields["status_code"] == 204 and result.fields["reason"] == ""


def test_response_headers_and_body():
    fields = parse_http(NGINX_200).fields
    assert ["Server", "nginx"] in fields["headers"]
    assert fields["body_len"] == len(b"hello lab\r\n\r\n")


def test_http_1_0_response():
    fields = parse_http(b"HTTP/1.0 301 Moved\r\nLocation: /x\r\n\r\n").fields
    assert fields["version"] == "HTTP/1.0" and fields["status_code"] == 301


# --- REQ-7.4: header chưa kết thúc trong packet -----------------------------

def test_missing_blank_line_is_incomplete_not_an_error():
    """Header tràn sang segment sau: không có lỗi, chỉ có cờ incomplete."""
    payload = b"GET / HTTP/1.1\r\nHost: 10.20.0.10\r\nUser-Agent: cu"
    result = parse_http(payload)
    assert result.error is None
    assert result.fields["incomplete"] is True
    # Header ĐẦY ĐỦ thì giữ; dòng cuối đang bị cắt giữa thì bỏ, vì
    # "User-Agent: cu" có thể là phần đầu của "User-Agent: curl/8.14.1".
    assert result.fields["headers"] == [["Host", "10.20.0.10"]]
    assert result.fields["method"] == "GET"


def test_incomplete_request_has_no_body():
    """Byte cuối buffer vẫn thuộc phần header -> không được đoán ra body."""
    fields = parse_http(b"POST / HTTP/1.1\r\nX: 1\r\nY: 2").fields
    assert fields["incomplete"] is True
    assert fields["body_len"] == 0 and fields["body_b64"] == ""


def test_request_line_alone_is_incomplete():
    fields = parse_http(b"GET /long-uri HTTP/1.1\r\n").fields
    assert fields["incomplete"] is True
    assert fields["uri"] == "/long-uri" and fields["headers"] == []


def test_not_even_one_full_line():
    """Chưa trọn một dòng: vẫn biết là request, chưa biết gì thêm."""
    result = parse_http(b"GET /index")
    assert result.error is None
    assert result.fields["kind"] == "request"
    assert result.fields["incomplete"] is True
    assert result.fields["method"] is None


def test_bare_lf_is_treated_as_incomplete():
    """CỐ TÌNH nghiêm ngặt: chỉ chấp nhận CRLF (xem docstring của http.py).

    Dễ tính với LF trần theo một cách khác server là điều kiện của request
    smuggling; event vẫn nói rõ đây là HTTP và chưa hoàn chỉnh.
    """
    result = parse_http(b"GET / HTTP/1.1\nHost: x\n\n")
    assert result.error is None
    assert result.fields["incomplete"] is True
    assert result.fields["headers"] == []


def test_complete_headers_clear_the_incomplete_flag():
    assert parse_http(CURL_GET).fields["incomplete"] is False


# --- REQ-7.5: không decode được -> lỗi, không dừng chương trình -------------

def test_non_ascii_byte_in_a_header_reports_a_decode_error():
    payload = b"GET / HTTP/1.1\r\nHost: 10.20.0.10\r\nX-Bad: caf\xe9\r\n\r\nb"
    result = parse_http(payload)
    assert result.error is not None
    assert "decode" in result.error
    assert "0xe9" in result.error                 # soi lại bằng xxd được
    # §5.4: giữ những gì đã parse được trước điểm lỗi
    assert result.fields["method"] == "GET"
    assert result.fields["headers"] == [["Host", "10.20.0.10"]]


def test_decode_error_stops_at_the_bad_line():
    """Dừng tại dòng sai, không đọc tiếp: đọc tiếp = tự đoán bên kia hiểu sao."""
    payload = (b"GET / HTTP/1.1\r\nA: 1\r\nB: \xff\r\nC: 3\r\n\r\n")
    result = parse_http(payload)
    assert result.error is not None and "line 3" in result.error
    assert result.fields["headers"] == [["A", "1"]]


def test_non_ascii_byte_in_the_start_line():
    result = parse_http(b"GET /caf\xc3\xa9 HTTP/1.1\r\nHost: x\r\n\r\n")
    assert result.error is not None and "decode" in result.error
    assert result.fields["kind"] == "request"
    assert result.fields["uri"] is None           # chưa đọc nổi start line


def test_non_ascii_in_the_body_is_not_an_error():
    """Chỉ phần HEADER buộc ASCII; body nhị phân là bình thường."""
    result = parse_http(b"POST / HTTP/1.1\r\nX: 1\r\n\r\n\xff\xfe\x00")
    assert result.error is None
    assert result.fields["body_len"] == 3


# --- status line và request line sai cú pháp --------------------------------

def test_status_code_2x0_is_an_error():
    result = parse_http(b"HTTP/1.1 2x0 OK\r\nX: 1\r\n\r\n")
    assert result.error is not None and "2x0" in result.error
    assert result.fields["status_code"] is None    # không bịa ra số
    assert result.fields["version"] == "HTTP/1.1"  # phần đọc được thì giữ


@pytest.mark.parametrize("code", [b"20", b"2000", b"", b"abc", b"-10", b"2 0"])
def test_status_code_must_be_exactly_three_digits(code):
    result = parse_http(b"HTTP/1.1 " + code + b" OK\r\n\r\n")
    assert result.error is not None
    assert result.fields["status_code"] is None


def test_non_ascii_digits_are_not_accepted_as_a_status_code():
    """str.isdigit() trả True cho "٢٠٠"; parser dùng tập ký tự tường minh."""
    result = parse_http("HTTP/1.1 ٢٠٠ OK\r\n\r\n".encode("utf-8"))
    assert result.error is not None
    assert result.fields["status_code"] is None


def test_status_line_with_no_code_at_all():
    result = parse_http(b"HTTP/1.1\r\nX: 1\r\n\r\n")
    assert result.error is not None and "status code" in result.error


def test_request_target_with_a_space_is_an_error():
    """"GET /a b HTTP/1.1": ca kinh điển làm proxy và server chia dòng khác nhau."""
    result = parse_http(b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n")
    assert result.error is not None and "4" in result.error
    assert result.fields["method"] == "GET"       # method vẫn giữ (REQ-14.1)
    assert result.fields["uri"] is None           # không đoán ranh giới


def test_request_line_with_two_parts_is_an_error():
    """HTTP/0.9 "GET /" — bài 1 chỉ hỗ trợ 1.x (Phụ lục C)."""
    assert parse_http(b"GET /\r\nHost: x\r\n\r\n").error is not None


def test_request_version_must_be_http_1_x():
    result = parse_http(b"GET / FOO/9.9\r\nHost: x\r\n\r\n")
    assert result.error is not None and "FOO/9.9" in result.error
    assert result.fields["version"] == "FOO/9.9"  # ghi đúng thứ có trên dây


# --- dòng header sai cú pháp ------------------------------------------------

def test_header_line_without_a_colon_is_an_error():
    result = parse_http(b"GET / HTTP/1.1\r\nHost: x\r\nrubbish\r\n\r\n")
    assert result.error is not None and "no colon" in result.error
    assert result.fields["headers"] == [["Host", "x"]]


def test_whitespace_before_the_colon_is_an_error():
    """RFC 9112 §5.1 buộc TỪ CHỐI: proxy cắt khoảng trắng, server thì không."""
    result = parse_http(b"GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\nabcde")
    assert result.error is not None
    assert "Content-Length " in result.error


def test_folded_header_line_is_an_error():
    """obs-fold (dòng nối bắt đầu bằng khoảng trắng) đã bỏ từ RFC 7230."""
    result = parse_http(b"GET / HTTP/1.1\r\nX: a\r\n  b\r\n\r\n")
    assert result.error is not None
    assert result.fields["headers"] == [["X", "a"]]


def test_empty_field_name_is_an_error():
    assert parse_http(b"GET / HTTP/1.1\r\n: value\r\n\r\n").error is not None


# --- I-1: không ném với dữ liệu bất kỳ --------------------------------------

@pytest.mark.parametrize("payload", [
    b"",
    b"\r\n\r\n",
    b"GET",
    b"HTTP/1.1",
    b"\xff" * 20,
    b"GET / HTTP/1.1\r\n" * 100,
    bytes(range(256)),
])
def test_never_raises_and_always_returns_the_full_key_set(payload):
    result = parse_http(payload)
    assert tuple(result.fields) == APP_FIELDS
    assert isinstance(result.fields["body_len"], int)
    assert result.fields["body_b64"].isascii()
