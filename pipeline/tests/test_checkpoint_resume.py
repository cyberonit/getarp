"""Ingest continuity across restarts.

tail() used to seek to end-of-file on every start, so whatever a sensor wrote
while the pipeline was down was skipped with nothing recording the gap. These
cover the resume path and the idempotency that makes at-least-once replay safe.
"""
import asyncio
import contextlib
import json
import os

import pytest

import ingestor


def _line(msg, ts="2026-08-07T10:00:00.000000+0000"):
    return json.dumps({
        "timestamp": ts, "event_type": "alert",
        "src_ip": "203.0.113.10", "src_port": 4444,
        "dest_ip": "192.0.2.1", "dest_port": 22,
        "alert": {"signature": msg, "severity": 2},
    }) + "\n"


@pytest.fixture
def log(tmp_path, monkeypatch):
    """A sensor log plus an isolated checkpoint dir."""
    monkeypatch.setattr(ingestor, "STATE_DIR", str(tmp_path / "state"))
    return tmp_path / "eve.json"


async def _drain(path, seconds=0.9):
    """Run the real tail() against path and return what it queued."""
    queue: asyncio.Queue = asyncio.Queue()
    task = asyncio.get_event_loop().create_task(
        ingestor.tail(str(path), queue, "suricata"))
    await asyncio.sleep(seconds)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    out = []
    while not queue.empty():
        out.append(queue.get_nowait()[1])
    return out


# ─────────────────────────── resume ───────────────────────────

async def test_first_start_skips_existing_history(log):
    """With no checkpoint there is nothing to resume from, so the pre-existing
    backlog is deliberately skipped rather than replayed in full."""
    log.write_text(_line("old-1") + _line("old-2"))
    assert await _drain(log) == []


async def test_records_written_while_down_are_not_lost(log):
    """The regression this whole change exists for."""
    log.write_text(_line("before"))
    await _drain(log)                      # first start: checkpoints at EOF

    log.write_text(log.read_text() + _line("while-down") + _line("while-down-2"))

    sigs = [r["alert"]["signature"] for r in await _drain(log)]
    assert sigs == ["while-down", "while-down-2"], \
        "records appended while the tail was stopped must be picked up on restart"


async def test_checkpoint_survives_and_advances(log):
    log.write_text(_line("a"))
    await _drain(log)
    first = ingestor._load_checkpoint(str(log))
    assert first is not None

    log.write_text(log.read_text() + _line("b"))
    await _drain(log)
    second = ingestor._load_checkpoint(str(log))

    assert second[0] == first[0], "same file, so the inode must not change"
    assert second[1] > first[1], "offset must advance past the new record"
    assert second[1] == log.stat().st_size, "should be caught up to end of file"


async def test_rotation_while_down_resumes_at_new_file(log):
    """A checkpoint naming a rotated-away inode must not be used as an offset
    into the replacement file — that would skip past real records."""
    log.write_text(_line("a") + _line("b") + _line("c"))
    await _drain(log)

    os.replace(str(log), str(log) + ".1")   # rotate: new inode at the old path
    log.write_text(_line("post-rotate"))

    sigs = [r["alert"]["signature"] for r in await _drain(log)]
    assert sigs == ["post-rotate"], \
        "must restart at offset 0 of the new file, not the stale offset"


async def test_truncation_while_down_resumes_from_start(log):
    """Truncated in place: same inode, but the saved offset now points past the
    end. Reading from there would skip everything written since."""
    log.write_text(_line("a") + _line("b") + _line("c"))
    await _drain(log)

    with open(log, "w") as fh:              # truncate, inode preserved
        fh.write(_line("fresh"))

    sigs = [r["alert"]["signature"] for r in await _drain(log)]
    assert sigs == ["fresh"]


async def test_corrupt_checkpoint_is_survivable(log):
    """A truncated or garbage state file must not wedge the tail."""
    log.write_text(_line("a"))
    await _drain(log)
    with open(ingestor._state_path(str(log)), "w") as fh:
        fh.write("{not json")

    log.write_text(log.read_text() + _line("b"))
    await _drain(log)                       # must not raise


async def test_unwritable_state_dir_does_not_break_ingest(log, monkeypatch):
    """Checkpointing fails soft. An unwritable state dir costs the resume
    ability — the tail degrades to the old seek-to-EOF behaviour — but it must
    never raise, because that would cost live traffic as well.
    """
    monkeypatch.setattr(ingestor, "STATE_DIR", "/proc/nonexistent/state")
    log.write_text(_line("a"))

    queue: asyncio.Queue = asyncio.Queue()
    task = asyncio.get_event_loop().create_task(
        ingestor.tail(str(log), queue, "suricata"))
    await asyncio.sleep(0.5)                       # let it open and seek
    with open(log, "a") as fh:                     # arrives while tailing
        fh.write(_line("live"))
    await asyncio.sleep(0.6)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    sigs = []
    while not queue.empty():
        sigs.append(queue.get_nowait()[1]["alert"]["signature"])
    assert sigs == ["live"], "live traffic must keep flowing without checkpoints"


# ─────────────────────── replay idempotency ───────────────────────

def test_event_id_is_stable_for_the_same_record():
    rec = json.loads(_line("dup"))
    assert ingestor._event_id("suricata", rec) == ingestor._event_id("suricata", rec)


def test_event_id_differs_across_records_and_sensors():
    a = json.loads(_line("one"))
    b = json.loads(_line("two"))
    assert ingestor._event_id("suricata", a) != ingestor._event_id("suricata", b)
    assert ingestor._event_id("suricata", a) != ingestor._event_id("extra", a)


def test_event_id_ignores_key_order():
    """The id must survive a re-serialization that reorders keys, or a replay
    would look like a new event."""
    a = {"event_type": "alert", "src_ip": "203.0.113.10"}
    b = {"src_ip": "203.0.113.10", "event_type": "alert"}
    assert ingestor._event_id("suricata", a) == ingestor._event_id("suricata", b)


async def test_replayed_event_is_not_double_counted(drive_consumer_replayed):
    """On conflict the insert returns no row, and the ips upsert plus the bus
    publish must both be skipped — otherwise a replay inflates event_count and
    re-queues enrichment for an IP already handled."""
    pool, r = await drive_consumer_replayed(
        [("suricata", json.loads(_line("replayed")))])

    sqls = [entry[1] for entry in pool.log]
    assert any("INSERT INTO events" in s for s in sqls), "insert is still attempted"
    assert not any("INSERT INTO ips" in s for s in sqls), \
        "ips upsert must be skipped when the event was already stored"
    assert r.streams == {}, "nothing should be published for a duplicate"


async def test_first_ingest_of_an_event_still_counts(drive_consumer):
    """Guard against the conflict path swallowing genuinely new events."""
    pool, r = await drive_consumer([("suricata", json.loads(_line("fresh")))])
    sqls = [entry[1] for entry in pool.log]
    assert any("INSERT INTO events" in s for s in sqls)
    assert any("INSERT INTO ips" in s for s in sqls)
    assert r.streams, "a new event must still reach the bus"
