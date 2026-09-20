# IDS/IPS — Hệ thống phát hiện và ngăn chặn xâm nhập

> **Repo:** https://github.com/TrinhQuangMinh123/NT204.R11.ANTN_TrinhQuangMinh_24521089
> **Lớp:** NT204.R11.ANTN · **Sinh viên:** Trịnh Quang Minh — 24521089

Đồ án tự xây dựng một IDS/IPS cơ bản, trong đó **từng chức năng được tự viết** thay vì dùng một engine
có sẵn (Snort/Suricata).

## 1. Mục tiêu

Nhu cầu cần đáp ứng: **học và hiểu IDS/IPS bằng cách tự lập trình từng thành phần** — bắt gói tin, bóc
tách giao thức, trích xuất đặc trưng, phát hiện tấn công và cảnh báo. Mục tiêu là hiểu cơ chế hoạt động,
không phải tạo ra một sản phẩm thương mại.

Ngoài phạm vi: machine learning, giao diện web, hiệu năng mức production, chống né tránh nâng cao.

## 2. Kiến trúc tổng quan

Toàn bộ hệ thống chạy bằng **Docker Compose**: các thành phần được đóng gói thành container và đặt trên
cùng một mạng ảo, gồm cảm biến IDS/IPS, máy mục tiêu và nguồn sinh traffic. Cách này cho phép tái hiện
lại từng kịch bản tấn công một cách lặp lại được và thu kết quả test trong môi trường cô lập.

Danh sách service, cấu hình mạng và công nghệ cụ thể của từng thành phần sẽ được bổ sung vào tài liệu
khi triển khai.

## 3. Chức năng dự kiến

| # | Task | Trạng thái |
|---|------|-----------|
| 1 | Thu thập packet | ☐ |
| 2 | Parser TCP, UDP | ☐ |
| 3 | Parser DNS, HTTP | ☐ |
| 4 | Trích xuất feature | ☐ |
| 5 | Phát hiện port scan | ☐ |
| 6 | Cảnh báo và ghi log | ☐ |
| 7 | Chức năng chặn (IPS) | ☐ |
| 8 | Test cases | ☐ |

## 4. Quy trình phát triển

- Mỗi task nhỏ, độc lập → **một commit riêng**, commit ngay khi xong.
- Mỗi test case → một commit riêng, kết quả lưu trong `TEST/`.
- Không gộp nhiều task/test case vào một commit; không sửa hay xoá lịch sử commit.
- Commit message ngắn, mô tả đúng việc đã làm: `Implement packet capture`, `Add port scan detection`,
  `Test port scan - case 01`.

## 5. Kiểm thử

Mỗi test case là một thư mục con trong `TEST/`, gồm mô tả kịch bản, cách tái hiện, dữ liệu đầu vào,
log/cảnh báo thu được và nhận xét kết quả.

## 6. Sử dụng công cụ AI

Công cụ: **Claude Opus 5**. Mục đích sử dụng:

- **Viết tài liệu** — soạn và chuẩn hoá `README.md`, ghi chú thiết kế, mô tả test case.
- **Lập kế hoạch** — chia đồ án thành các task nhỏ, độc lập và sắp xếp thứ tự thực hiện.
- **Thảo luận quan điểm và ý tưởng** — so sánh các hướng thiết kế để tự chọn hướng phù hợp.
- **Hỗ trợ debug** — giải thích traceback, chỉ ra nguyên nhân khi parser đọc sai byte hoặc luật phát
  hiện báo nhầm.
- **Giải thích kiến thức nền** — cấu trúc header, TCP handshake, hành vi của các kiểu quét cổng, để
  hiểu *tại sao* code cần viết như vậy.

**Cam kết:** AI chỉ đóng vai trò hỗ trợ tài liệu, định hướng và giải thích. Tôi tự viết, tự đọc hiểu và
có thể giải thích từng dòng mã nguồn trong repo này. Các tệp có sử dụng AI hỗ trợ được liệt kê bên dưới
và cập nhật trong suốt quá trình làm bài.

| Tệp | Mức độ hỗ trợ của AI |
|-----|----------------------|
| `README.md` | Soạn thảo nội dung tài liệu có giám sát|
