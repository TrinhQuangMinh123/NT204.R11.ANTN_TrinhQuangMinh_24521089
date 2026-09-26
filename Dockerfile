# ADR-1: Debian slim, pin tới bản patch để build lại ra cùng một môi trường
FROM python:3.12.14-slim

# Không ghi __pycache__ vào repo đang bind mount; log ra ngay (không buffer)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Mã nguồn không COPY vào image: compose bind mount repo vào /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
