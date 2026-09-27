# Cùng Debian 13 (trixie) với python:3.12.14-slim của sensor → cả lab chỉ có một
# hệ đóng gói, tên gói và cách apt giống nhau.
FROM debian:13-slim

# curl            sinh traffic HTTP (TC-04, 05, 06, 13)
# bind9-dnsutils  lệnh dig (TC-07, 08)
# netcat-openbsd  gõ SMTP thủ công (TC-09, 10)
# traceroute      chứng minh gói thật sự đi qua sensor (V1.1)
# tcpdump         ghi PCAP làm bằng chứng test
# iproute2        lệnh ip route, tự đặt đường sang mạng victim
# iputils-ping    kiểm tra thông mạng
# --no-install-recommends: không kéo gói gợi ý → danh sách phần mềm trong lab
# đúng bằng những gì liệt kê trên, không có thứ lọt vào ngoài ý muốn.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl bind9-dnsutils netcat-openbsd traceroute tcpdump iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*
