# Admin web app image: unprivileged user, no Docker CLI, no shell tools beyond the base image.
FROM python:3.13-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && groupadd -g 10001 ivadmin && useradd -u 10001 -g 10001 -M -d /nonexistent -s /usr/sbin/nologin ivadmin
COPY app.py /app/app.py
WORKDIR /app
USER 10001:10001
EXPOSE 18090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "18090", "--workers", "1", "--no-access-log", "--log-level", "warning", "--proxy-headers", "--forwarded-allow-ips", "*"]
