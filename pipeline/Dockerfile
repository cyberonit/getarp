FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ingestor.py .
RUN adduser --disabled-password --no-create-home appuser
USER appuser
CMD ["python", "-u", "ingestor.py"]
