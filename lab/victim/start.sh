#!/bin/sh
# Victim chạy ba dịch vụ trong một container (ADR-15), nên phải tự chọn tiến
# trình nào giữ foreground — container sống đúng bằng đời tiến trình cuối cùng:
#   dnsmasq   tự daemon hoá, gọi xong là tự lùi xuống nền
#   aiosmtpd  chạy foreground nên phải đẩy nền bằng &
#   nginx     exec để thành PID 1 → nhận SIGTERM khi `docker compose down`
# Nếu nginx chết, container dừng và hai tiến trình kia bị dọn theo.
set -e

dnsmasq

# -n: không setuid xuống 'nobody'. Container đã bị bó bằng cap_drop nên hạ quyền
# thêm không đổi gì, mà -n làm lỗi hiện ra rõ thay vì chết lặng ở bước setuid.
# Nghe 0.0.0.0 vì container chỉ có một interface lab; mọi địa chỉ IP vẫn nằm
# trong compose.yaml để đối chiếu Phụ lục E ở một chỗ duy nhất.
python3 -m aiosmtpd -n -l 0.0.0.0:25 &

exec nginx -g 'daemon off;'
