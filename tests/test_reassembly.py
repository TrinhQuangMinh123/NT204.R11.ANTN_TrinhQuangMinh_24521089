"""Phase 4 — MailBuffer: nối mảnh, cắt thư, giữ ngân sách (REQ-40, I-19).

T4.1: chỉ thử bộ đệm; việc nối nó vào FlowTracker thuộc T4.2.
"""
from idps.process.reassembly import MailBuffer

MAIL = b"Subject: hi\r\n\r\nhello world"
END = b"\r\n.\r\n"


def test_whole_mail_in_one_feed():
    buf = MailBuffer(1000)
    assert buf.feed(MAIL + END) == [MAIL]
    assert buf.buffered == 0


def test_mail_split_over_three_feeds():
    buf = MailBuffer(1000)
    data = MAIL + END
    assert buf.feed(data[:10]) == []
    assert buf.feed(data[10:20]) == []
    assert buf.feed(data[20:]) == [MAIL]


def test_end_marker_straddles_two_feeds():
    """Dấu kết thúc bị cắt đôi giữa hai packet vẫn phải được nhận ra."""
    for cut in range(1, len(END)):
        buf = MailBuffer(1000)
        assert buf.feed(MAIL + END[:cut]) == []
        assert buf.feed(END[cut:]) == [MAIL], f"cut at {cut}"


def test_dot_stuffing_removed():
    buf = MailBuffer(1000)
    stuffed = b"line one\r\n..dot line\r\n...two dots"
    assert buf.feed(stuffed + END) == [b"line one\r\n.dot line\r\n..two dots"]


def test_dot_stuffing_on_first_line():
    buf = MailBuffer(1000)
    assert buf.feed(b"..first" + END) == [b".first"]


def test_empty_mail():
    """Thư rỗng: dấu kết thúc nằm ngay đầu bộ đệm, không có CRLF đứng trước."""
    buf = MailBuffer(1000)
    assert buf.feed(b".\r\n") == [b""]


def test_empty_mail_split():
    buf = MailBuffer(1000)
    assert buf.feed(b".") == []
    assert buf.feed(b"\r\n") == [b""]


def test_two_mails_pipelined():
    buf = MailBuffer(1000)
    assert buf.feed(MAIL + END + b"second" + END) == [MAIL, b"second"]
    assert buf.buffered == 0


def test_flush_returns_unterminated_remainder():
    buf = MailBuffer(1000)
    buf.feed(MAIL)
    assert buf.flush() == [MAIL]
    assert buf.buffered == 0
    assert buf.flush() == []


def test_flush_keeps_mail_after_a_complete_one():
    buf = MailBuffer(1000)
    assert buf.feed(MAIL + END + b"part") == [MAIL]
    assert buf.flush() == [b"part"]


def test_limit_stops_collecting():
    buf = MailBuffer(20)
    assert buf.feed(b"a" * 15) == []
    assert not buf.stopped
    assert buf.feed(b"b" * 15) == []          # chỉ còn chỗ cho 5 byte
    assert buf.stopped
    assert buf.reasons == ["reassembly_limit=20"]
    assert buf.flush() == [b"a" * 15 + b"b" * 5]
    assert buf.feed(b"more") == []            # đã dừng: bỏ byte đến sau
    assert buf.flush() == []


def test_limit_counts_emitted_mails():
    """Thư đã cắt ra vẫn chiếm ngân sách (REQ-40.4): nhiều thư nhỏ không lách được."""
    buf = MailBuffer(30)
    assert buf.feed(b"a" * 10 + END) == [b"a" * 10]     # 10 byte thư đã dùng
    assert buf.feed(b"b" * 10 + END) == [b"b" * 10]     # 20
    buf.feed(b"c" * 30 + END)                           # chỉ còn chỗ cho 10
    assert buf.stopped
    assert buf.reasons == ["reassembly_limit=30"]


def test_complete_mail_inside_budget_still_returned():
    buf = MailBuffer(8)
    assert buf.feed(b"abc" + END + b"zzzzzzzz") == [b"abc"]
    assert buf.stopped


def test_budget():
    """I-19: bộ đệm + thư đã cắt ≤ giới hạn ở MỌI thời điểm, dù payload lớn đến đâu."""
    limit = 50
    buf = MailBuffer(limit)
    emitted = 0
    for chunk in (b"x" * 7, END, b"y" * 30, b"z" * 100, END, b"w" * 5):
        for mail in buf.feed(chunk):
            emitted += len(mail)
        assert buf.buffered + emitted <= limit
    for mail in buf.flush():
        emitted += len(mail)
    assert emitted <= limit
