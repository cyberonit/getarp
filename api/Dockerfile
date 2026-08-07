FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Identities pinned numerically instead of left to adduser's "next free id".
# gid 999 (sensorlogs) owns every file on the honeypot_logs volume, which this
# container mounts read-only to serve raw log views: the volume directory is
# setgid so sensor logs inherit the group whatever the writer's umask, and
# membership here is what makes those files readable without depending on the
# world-read bit staying set. Keep in sync with pipeline/Dockerfile.
RUN groupadd -g 999 sensorlogs \
    && groupadd -g 1000 appuser \
    && useradd -u 1000 -g 1000 -G sensorlogs --no-create-home appuser
USER appuser
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
