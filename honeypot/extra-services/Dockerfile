FROM python:3.12-slim
# No third-party deps: stdlib asyncio only -> tiny, hard-to-exploit image.
WORKDIR /app
COPY services.py .
RUN useradd -r -u 10001 hp && mkdir -p /var/log/honeypot && chown hp /var/log/honeypot
USER hp
ENV HP_LOG=/var/log/honeypot/extra.json
CMD ["python", "-u", "services.py"]
