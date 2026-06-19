#!/usr/bin/env python3
"""
Extra-services honeypot for getarp.net.

Low-/medium-interaction emulators that present believable banners and capture
connection + credential attempts, then log a canonical JSON record per event to
the shared logs volume. NOTHING is executed; we only present protocol greetings
and record what the attacker sends. This is a defensive sensor.

Services:
  HTTP   :8080, :8081   fake admin/login page, logs method+path+UA
  MySQL  :3306          fake "DB": server greeting + capture login username
  FTP    :2121          220 banner + capture USER/PASS
  REDIS  :6379          PING/AUTH/INFO emulation + capture AUTH password
"""
import asyncio
import json
import os
import struct
import uuid
from datetime import datetime, timezone

LOG_PATH = os.environ.get("HP_LOG", "/var/log/honeypot/extra.json")
_log_lock = asyncio.Lock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def log_event(**fields) -> None:
    record = {
        "event_id": str(uuid.uuid4()),
        "ts": now(),
        "sensor": "extra",
        **fields,
    }
    line = json.dumps(record, default=str) + "\n"
    async with _log_lock:
        # append-only; volume is writable, container rootfs is read-only
        with open(LOG_PATH, "a") as fh:
            fh.write(line)


def peer(writer) -> tuple[str, int]:
    info = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    return info[0], info[1]


# ────────────────────────────── HTTP ──────────────────────────────
FAKE_LOGIN = (
    b"<!doctype html><html><head><title>Admin Portal</title></head>"
    b"<body><h2>getarp internal - sign in</h2>"
    b"<form method=post action=/login>"
    b"<input name=user><input name=pass type=password>"
    b"<button>Login</button></form></body></html>"
)


async def handle_http(reader, writer, dst_port):
    ip, sport = peer(writer)
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=8)
    except asyncio.TimeoutError:
        data = b""
    text = data.decode("latin-1", "replace")
    request_line = text.split("\r\n", 1)[0]
    method = request_line.split(" ")[0] if request_line else ""
    path = request_line.split(" ")[1] if request_line.count(" ") >= 1 else ""
    ua = ""
    body = ""
    for ln in text.split("\r\n"):
        if ln.lower().startswith("user-agent:"):
            ua = ln.split(":", 1)[1].strip()
    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1]

    await log_event(
        service="http", dst_port=dst_port, src_ip=ip, src_port=sport,
        event_type="login_attempt" if method == "POST" else "connect",
        command=f"{method} {path}",
        raw={"request_line": request_line, "user_agent": ua, "body": body[:512]},
    )
    resp = (
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\nConnection: close\r\n"
        b"Content-Length: " + str(len(FAKE_LOGIN)).encode() + b"\r\n\r\n" + FAKE_LOGIN
    )
    writer.write(resp)
    await writer.drain()
    writer.close()


# ──────────────────────────── MySQL (fake DB) ────────────────────────────
def mysql_greeting() -> bytes:
    # Protocol 10 handshake — enough to make scanners/clients send a login packet.
    proto = b"\x0a"
    version = b"8.0.36-0ubuntu0.1\x00"
    thread_id = struct.pack("<I", 1234)
    salt1 = b"abcdefgh"
    payload = (
        proto + version + thread_id + salt1 + b"\x00"
        + struct.pack("<H", 0xffff)            # capability flags low
        + b"\x21"                               # charset utf8
        + struct.pack("<H", 0x0002)            # status
        + struct.pack("<H", 0xc1ff)            # capability flags high
        + b"\x15" + b"\x00" * 10
        + b"ijklmnopqrst\x00"                  # salt2
        + b"mysql_native_password\x00"
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"  # length + seq 0
    return header + payload


async def handle_mysql(reader, writer, dst_port):
    ip, sport = peer(writer)
    await log_event(service="mysql", dst_port=dst_port, src_ip=ip, src_port=sport,
                    event_type="connect", raw={"note": "fake-db greeting sent"})
    writer.write(mysql_greeting())
    await writer.drain()
    try:
        login = await asyncio.wait_for(reader.read(2048), timeout=8)
    except asyncio.TimeoutError:
        login = b""
    username = ""
    if len(login) > 36:
        try:
            # username is a null-terminated string after the 32-byte filler @ offset 36
            uname_bytes = login[36:].split(b"\x00", 1)[0]
            username = uname_bytes.decode("latin-1", "replace")
        except Exception:
            username = ""
    await log_event(service="mysql", dst_port=dst_port, src_ip=ip, src_port=sport,
                    event_type="login_attempt", username=username,
                    raw={"login_len": len(login)})
    # deny with a realistic auth error
    err = b"\xff\x15\x04#28000Access denied for user"
    writer.write(struct.pack("<I", len(err))[:3] + b"\x02" + err)
    await writer.drain()
    writer.close()


# ─────────────────────────────── FTP ───────────────────────────────
async def handle_ftp(reader, writer, dst_port):
    ip, sport = peer(writer)
    await log_event(service="ftp", dst_port=dst_port, src_ip=ip, src_port=sport,
                    event_type="connect")
    writer.write(b"220 (vsFTPd 3.0.5)\r\n")
    await writer.drain()
    user = passwd = ""
    try:
        for _ in range(4):
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not line:
                break
            cmd = line.decode("latin-1", "replace").strip()
            if cmd.upper().startswith("USER"):
                user = cmd[5:]
                writer.write(b"331 Please specify the password.\r\n")
            elif cmd.upper().startswith("PASS"):
                passwd = cmd[5:]
                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"530 Please login with USER and PASS.\r\n")
            await writer.drain()
    except asyncio.TimeoutError:
        pass
    if user or passwd:
        await log_event(service="ftp", dst_port=dst_port, src_ip=ip, src_port=sport,
                        event_type="login_attempt", username=user, password=passwd)
    writer.close()


# ────────────────────────────── REDIS ──────────────────────────────
async def handle_redis(reader, writer, dst_port):
    ip, sport = peer(writer)
    await log_event(service="redis", dst_port=dst_port, src_ip=ip, src_port=sport,
                    event_type="connect")
    try:
        for _ in range(6):
            data = await asyncio.wait_for(reader.read(1024), timeout=10)
            if not data:
                break
            text = data.decode("latin-1", "replace")
            upper = text.upper()
            if "AUTH" in upper:
                # capture the password the bot is trying
                parts = text.replace("\r\n", " ").split()
                pw = parts[-1] if parts else ""
                await log_event(service="redis", dst_port=dst_port, src_ip=ip,
                                src_port=sport, event_type="login_attempt", password=pw)
                writer.write(b"-ERR invalid password\r\n")
            elif "PING" in upper:
                writer.write(b"+PONG\r\n")
            elif "INFO" in upper:
                info = b"redis_version:7.2.4\r\nrole:master"
                writer.write(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
            else:
                await log_event(service="redis", dst_port=dst_port, src_ip=ip,
                                src_port=sport, event_type="command",
                                command=text.strip()[:200])
                writer.write(b"+OK\r\n")
            await writer.drain()
    except asyncio.TimeoutError:
        pass
    writer.close()


# ───────────────────────────── wiring ─────────────────────────────
async def make_server(handler, port):
    async def cb(r, w):
        try:
            await handler(r, w, port)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:  # never crash the listener on one bad client
            ip, _ = peer(w)
            await log_event(service="error", dst_port=port, src_ip=ip,
                            event_type="error", raw={"err": str(e)})
    srv = await asyncio.start_server(cb, "0.0.0.0", port)
    return srv


async def main():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    listeners = [
        (handle_http, 8080),
        (handle_http, 8081),
        (handle_mysql, 3306),
        (handle_ftp, 2121),
        (handle_redis, 6379),
    ]
    servers = [await make_server(h, p) for h, p in listeners]
    print(f"[extra-services] listening on: {[p for _, p in listeners]}", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
