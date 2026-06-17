FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir redis==5.0.8 asyncpg==0.29.0 httpx==0.27.2
COPY engine.py .
COPY correlation/ ./correlation/
COPY behavioral/ ./behavioral/
CMD ["python", "-u", "engine.py"]
