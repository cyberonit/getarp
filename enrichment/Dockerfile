FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir redis==5.0.8 asyncpg==0.29.0 httpx==0.27.2 maxminddb==2.6.2
COPY base.py providers.py feeds.py worker.py heartbeat.py retry.py healthcheck.py ./
# uid/gid pinned rather than left to adduser's "next free id". This container
# does not touch honeypot_logs, so it is not in the sensorlogs group — but the
# geoip volume below is seeded from this image and keeps its ownership for the
# life of the volume, so an appuser whose uid moved on a rebuild would lose
# write access to it and the GeoLite2 databases would stop updating.
RUN groupadd -g 1000 appuser \
    && useradd -u 1000 -g 1000 --no-create-home appuser \
    && mkdir /geoip && chown appuser:appuser /geoip
USER appuser
CMD ["python", "-u", "worker.py"]
