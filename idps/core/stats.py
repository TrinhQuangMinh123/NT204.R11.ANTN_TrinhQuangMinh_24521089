"""Stats — đếm kết quả của một lần chạy để in dòng tổng kết (REQ-13.5)."""


class Stats:
    """processed / unknown / malformed.

    Ba con số KHÔNG chồng nhau vì `status` của một event chỉ nhận đúng một
    trong ba giá trị ok/unknown/malformed (compute_status: malformed >
    unknown > ok). Nhờ vậy "processed - unknown - malformed" chính là số
    packet parse trọn vẹn, đọc dòng thống kê là biết ngay chất lượng lần chạy.
    """

    def __init__(self):
        self.processed = 0
        self.unknown = 0
        self.malformed = 0

    def add(self, event: dict) -> None:
        """Mỗi event được xử lý đếm đúng một lần (REQ-12.1)."""
        self.processed += 1
        status = event["status"]
        if status == "unknown":
            self.unknown += 1
        elif status == "malformed":
            self.malformed += 1

    def line(self) -> str:
        """Dòng in ra stdout khi kết thúc (design §5.5).

        Dạng `khoá=giá trị` cách nhau bằng dấu cách để vừa đọc được bằng mắt
        khi vấn đáp, vừa `grep`/`cut` được trong run.log của các test case.
        """
        return (
            f"processed={self.processed} "
            f"unknown={self.unknown} "
            f"malformed={self.malformed}"
        )
