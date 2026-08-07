FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ingestor.py heartbeat.py retry.py healthcheck.py ./
# Identities are pinned numerically instead of being left to adduser's "next
# free id". Three sensors write the honeypot_logs volume as three different
# uids and four services read it; none of that lines up unless every image
# agrees on the numbers, and an id that quietly moves on a rebuild is how this
# volume has broken before.
#
# gid 999 (sensorlogs) owns every file on that volume — the volume directory is
# setgid, so a sensor log inherits the group whatever the writer's umask is.
# Membership here is what lets this container read a 0640 log; without it the
# reads only work while the sensors happen to leave the world-read bit on.
#
# uid 1000 is pinned for a second reason: the pipeline_state volume was seeded
# from this image and keeps that ownership for the life of the volume, so an
# appuser whose uid moved would silently lose the ability to persist read
# offsets — and the ingestor would go back to skipping to EOF on every restart.
RUN groupadd -g 999 sensorlogs \
    && groupadd -g 1000 appuser \
    && useradd -u 1000 -g 1000 -G sensorlogs --no-create-home appuser
# Checkpoint directory, created here with appuser ownership so the named volume
# mounted over it inherits that uid/gid — Docker seeds an empty named volume
# from the image path, permissions included. Without this the volume would be
# root-owned and the non-root ingestor could not persist read offsets, which
# fails soft (it logs and keeps ingesting) and so would go unnoticed.
RUN mkdir -p /var/lib/pipeline && chown appuser:appuser /var/lib/pipeline
USER appuser
CMD ["python", "-u", "ingestor.py"]
