"""NUL sanitizing: Postgres stores NUL (U+0000) in neither text ("invalid byte
sequence for encoding UTF8: 0x00") nor jsonb ("unsupported Unicode escape
sequence"), so an attacker payload containing one used to fail the insert and
drop the whole event — no events row, no ips upsert, no analytics stream, no
enrich queue. A source could go unrecorded just by sending a NUL byte."""
import json

import ingestor


def _cowrie_cmd(src_ip, command, username=None):
    return ("cowrie", {
        "timestamp": "2026-08-06T11:20:00.000000Z",
        "eventid": "cowrie.command.input",
        "src_ip": src_ip, "src_port": 51000, "dst_port": 2222,
        "session": "abc123",
        "username": username,
        "input": command,
    })


def test_strip_nulls_handles_nested_structures():
    dirty = {
        "command": "wget\x00evil.sh",
        "severity": 3,
        "port": None,
        "raw": {"nested": {"deep": "a\x00b"}, "list": ["x\x00y", 5], "clean": "fine"},
    }
    clean = ingestor._strip_nulls(dirty)
    assert clean["command"] == f"wget{ingestor.NUL_REPLACEMENT}evil.sh"
    assert clean["raw"]["nested"]["deep"] == f"a{ingestor.NUL_REPLACEMENT}b"
    assert clean["raw"]["list"][0] == f"x{ingestor.NUL_REPLACEMENT}y"
    # non-strings pass through untouched
    assert clean["severity"] == 3 and clean["port"] is None
    assert clean["raw"]["list"][1] == 5
    assert clean["raw"]["clean"] == "fine"


def test_sanitized_payload_is_storable():
    """Neither a raw NUL byte (text columns) nor a \\u0000 escape (jsonb) may
    survive into what we hand asyncpg."""
    clean = ingestor._strip_nulls({"raw": {"cmd": "a\x00b", "u": "n\x00"}})
    dumped = json.dumps(clean["raw"])
    assert "\x00" not in dumped
    assert "\\u0000" not in dumped


async def test_event_with_nul_is_still_ingested(drive_consumer):
    """The whole point: a NUL in the payload must not make the event vanish.
    It must still insert, upsert the ip, hit the bus and queue for enrichment."""
    pool, r = await drive_consumer([
        _cowrie_cmd("203.0.113.77", "cat /etc/passwd\x00\x00", username="ro\x00ot"),
    ])
    sqls = [entry[1] for entry in pool.log]
    assert any("INSERT INTO events" in s for s in sqls)
    assert any("INSERT INTO ips" in s for s in sqls)
    events = r.streams[ingestor.EVENTS_STREAM]
    assert len(events) == 1
    assert events[0]["src_ip"] == "203.0.113.77"
    assert r.streams[ingestor.ENRICH_STREAM] == [{"src_ip": "203.0.113.77"}]


async def test_nul_free_of_raw_bytes_in_db_args(drive_consumer):
    """Nothing handed to asyncpg may still contain a NUL, in any column."""
    pool, _ = await drive_consumer([
        _cowrie_cmd("203.0.113.78", "bad\x00cmd", username="u\x00"),
    ])
    # Guard against a vacuous pass: if the insert were rejected outright the
    # log would be empty and the loop below would assert nothing at all.
    assert pool.log, "no DB calls recorded — event was dropped, not sanitized"
    checked = 0
    for _kind, _sql, args in pool.log:
        for a in args:
            if isinstance(a, str):
                assert "\x00" not in a
                assert "\\u0000" not in a
                checked += 1
    assert checked, "no string arguments were inspected"


async def test_clean_events_are_unchanged(drive_consumer):
    """Sanitizing must be a no-op for ordinary traffic."""
    pool, r = await drive_consumer([
        _cowrie_cmd("203.0.113.79", "uname -a", username="root"),
    ])
    events = r.streams[ingestor.EVENTS_STREAM]
    assert len(events) == 1
    assert events[0]["command"] == "uname -a"
    assert ingestor.NUL_REPLACEMENT not in events[0]["command"]
