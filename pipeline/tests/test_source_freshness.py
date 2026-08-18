"""
A tail loop that is running is not the same thing as a source that is producing.

On 2026-08-08 cowrie.json stopped being written, and on 2026-08-10 extra.json
did too — both because the sensors lost write access to the shared log volume.
The pipeline reported healthy for the ten days that followed: the tail loops
were polling their files exactly as designed, and polling an idle file is a
loop working correctly. Two thirds of ingest was gone with no signal anywhere.

These cover the separate data-freshness beat added for that, and — just as
importantly — that it is kept out of the watchdog's spec, because restarting
the pipeline cannot fix a file the sensor is failing to write and would only
crash-loop it.
"""
import asyncio
import contextlib
import os
import time

import pytest

import heartbeat
import ingestor


@pytest.fixture
def beats(tmp_path, monkeypatch):
    """Point the heartbeat files at a temp dir, isolated per test."""
    monkeypatch.setattr(heartbeat, "HEARTBEAT_DIR", str(tmp_path))
    heartbeat._last.clear()
    return tmp_path


def _age_beat(beats, name, seconds):
    """Backdate a beat file, standing in for a source that has gone quiet."""
    path = os.path.join(beats, name)
    old = time.time() - seconds
    os.utime(path, (old, old))


async def _tail_briefly(path, queue, append=None):
    """Run the real tail() for a moment, optionally appending a line once it is
    following. With no checkpoint on disk tail() starts at end-of-file by
    design, so anything written beforehand is deliberately not ingested — the
    line has to arrive while it is watching."""
    task = asyncio.get_event_loop().create_task(
        ingestor.tail(str(path), queue, "suricata"))
    await asyncio.sleep(0.3)
    if append:
        with open(path, "a") as fh:
            fh.write(append)
    await asyncio.sleep(0.6)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def test_reading_a_line_beats_the_data_beat(beats, tmp_path):
    """The beat tracks lines read, not loop iterations."""
    log = tmp_path / "eve.json"
    log.write_text("")

    queue: asyncio.Queue = asyncio.Queue()
    asyncio.run(_tail_briefly(log, queue,
                              append='{"event_type":"alert","src_ip":"1.2.3.4"}\n'))

    assert heartbeat.age("data:eve.json") is not None, \
        "reading a line did not record a data beat"


def test_idle_tail_does_not_refresh_the_data_beat(beats, tmp_path):
    """The regression itself: a live loop over a file nothing is writing must
    leave the data beat to go stale, even though the liveness beat stays fresh."""
    log = tmp_path / "eve.json"
    log.write_text("")          # exists, but nobody is appending to it

    queue: asyncio.Queue = asyncio.Queue()
    asyncio.run(_tail_briefly(log, queue))

    live = heartbeat.age("tail:eve.json")
    assert live is not None and live < 5, "the tail loop should be beating"
    assert heartbeat.age("data:eve.json") is None, \
        "an idle source refreshed its data beat — the outage would stay invisible"


def test_stale_source_is_unhealthy_but_not_a_watchdog_restart(beats):
    """A silent source turns the container unhealthy, and nothing more."""
    specs = {"data:cowrie.json": 6 * 3600}
    heartbeat.start(specs)
    _age_beat(beats, "data:cowrie.json", 10 * 24 * 3600)   # the real outage

    name, seen, max_age = heartbeat.stale(specs)
    assert name == "data:cowrie.json"
    assert seen > max_age

    # and the watchdog must not be watching it
    assert not any(k.startswith("data:") for k in ingestor.HEARTBEATS), \
        ("data beats leaked into HEARTBEATS: the watchdog would exit the "
         "process over a sensor fault a restart cannot fix")


def test_quiet_source_within_threshold_stays_healthy(beats):
    """A honeypot with nothing to report is not a broken honeypot."""
    specs = dict(ingestor.SOURCE_FRESHNESS)
    heartbeat.start(specs)
    for name in specs:
        _age_beat(beats, name, 3600)      # an hour of quiet

    assert heartbeat.stale(specs) is None, \
        "an hour of quiet was reported as a dead source"


def test_thresholds_cover_every_ingested_file():
    """A source added to FILES without a freshness threshold would be exactly
    as invisible as the two that broke."""
    assert set(ingestor.SOURCE_FRESHNESS) == {f"data:{f}" for f in ingestor.FILES}
