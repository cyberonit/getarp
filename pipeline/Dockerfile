FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ingestor.py .
RUN adduser --disabled-password --no-create-home appuser
# Checkpoint directory, created here with appuser ownership so the named volume
# mounted over it inherits that uid/gid — Docker seeds an empty named volume
# from the image path, permissions included. Without this the volume would be
# root-owned and the non-root ingestor could not persist read offsets, which
# fails soft (it logs and keeps ingesting) and so would go unnoticed.
RUN mkdir -p /var/lib/pipeline && chown appuser:appuser /var/lib/pipeline
USER appuser
CMD ["python", "-u", "ingestor.py"]
