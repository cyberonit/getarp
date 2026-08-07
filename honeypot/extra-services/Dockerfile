FROM python:3.12-slim
# No third-party deps: stdlib asyncio only -> tiny, hard-to-exploit image.
WORKDIR /app
COPY services.py .
# Both ids pinned. The uid always was; the gid was not — useradd took the next
# free system gid, which landed on 999 by luck and matched the group the log
# volume is owned by. The whole shared-group scheme rested on that coincidence,
# and any package added to this image ahead of this line could have moved it.
# services.py sets umask 002 to match, so a log file it creates itself keeps
# the group's write bit (see the comment there).
RUN groupadd -g 999 sensorlogs \
    && useradd -r -u 10001 -g 999 hp \
    && mkdir -p /var/log/honeypot && chown hp:sensorlogs /var/log/honeypot \
    && chmod 2775 /var/log/honeypot
USER hp
ENV HP_LOG=/var/log/honeypot/extra.json
CMD ["python", "-u", "services.py"]
