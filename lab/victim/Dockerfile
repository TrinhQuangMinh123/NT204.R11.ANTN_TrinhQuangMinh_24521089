# Debian 13 (trixie) như attacker và sensor → cả lab một hệ đóng gói duy nhất.
# Không dùng image nginx chính thức vì T1.5/T1.6 sẽ thêm dnsmasq và SMTP vào cùng
# container này, khi đó cần apt của Debian và một script khởi động tự viết.
FROM debian:13-slim

# nginx: dịch vụ HTTP (TC-04, 05, 06, 13) · iproute2: đặt route về mạng attacker
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx iproute2 \
 && rm -rf /var/lib/apt/lists/*

# Body ngắn và cố định để response HTTP trong test luôn giống nhau từng byte
RUN printf 'victim lab\n' > /var/www/html/index.html

# Thay site mặc định của Debian bằng cấu hình của mình
RUN rm -f /etc/nginx/sites-enabled/default
COPY site.conf /etc/nginx/conf.d/site.conf

# Log ra stdout/stderr thay vì file. Hai lý do: (1) /var/log/nginx/*.log thuộc
# www-data:adm mode 640 nên nginx master (root) không mở được khi đã bỏ
# DAC_OVERRIDE — đổ ra fd có sẵn thì không cần thêm capability nào;
# (2) `docker compose logs victim` xem được access log để đối chiếu với gói đã bắt.
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
 && ln -sf /dev/stderr /var/log/nginx/error.log

# nginx foreground để làm PID 1 → nhận SIGTERM khi compose down (command trong
# compose.yaml ghi đè dòng này để thêm route trước khi exec nginx)
CMD ["nginx", "-g", "daemon off;"]
