FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir redis==5.0.8 asyncpg==0.29.0 httpx==0.27.2
COPY engine.py heartbeat.py retry.py healthcheck.py ./
COPY correlation/ ./correlation/
COPY behavioral/ ./behavioral/
# uid/gid pinned rather than left to adduser's "next free id". This container
# mounts no shared volume, so it needs no group beyond its own — the pinning is
# here so every service in the stack lands on the same identity and a rebuild
# cannot move it.
RUN groupadd -g 1000 appuser \
    && useradd -u 1000 -g 1000 --no-create-home appuser
USER appuser
CMD ["python", "-u", "engine.py"]
