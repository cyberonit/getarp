"""Self-IP filter: Suricata response-direction alerts carry the sensor's own
IP as src_ip (dst_port = the attacker's ephemeral port); ingesting them makes
the scan detector report the honeypot as a vertical scanner of itself."""
import ingestor


def _suricata_alert(src_ip, src_port, dest_ip, dest_port):
    return ("suricata", {
        "timestamp": "2026-07-19T10:56:53.558674+0000",
        "event_type": "alert",
        "src_ip": src_ip, "src_port": src_port,
        "dest_ip": dest_ip, "dest_port": dest_port,
        "app_proto": "ftp",
        "alert": {
            "signature": "ET SCAN Potential FTP Brute-Force attempt response",
            "severity": 2,
        },
    })


async def test_own_ip_events_are_dropped(drive_consumer):
    """The honeypot's FTP '530' replies during a brute-force must not be
    stored, streamed, or queued for enrichment."""
    pool, r = await drive_consumer([
        _suricata_alert("192.0.2.1", 21, "203.0.113.10", 57889),
        _suricata_alert("192.0.2.1", 21, "203.0.113.10", 57801),
    ])
    assert pool.log == []
    assert r.streams == {}


async def test_attacker_events_still_flow(drive_consumer):
    """The inbound leg of the same brute-force is real signal and must keep
    flowing: events insert, ips upsert, analytics stream, enrich queue."""
    pool, r = await drive_consumer([
        _suricata_alert("203.0.113.10", 57889, "192.0.2.1", 21),
    ])
    sqls = [entry[1] for entry in pool.log]
    assert any("INSERT INTO events" in s for s in sqls)
    assert any("INSERT INTO ips" in s for s in sqls)
    events = r.streams[ingestor.EVENTS_STREAM]
    assert len(events) == 1
    assert events[0]["src_ip"] == "203.0.113.10"
    assert r.streams[ingestor.ENRICH_STREAM] == [{"src_ip": "203.0.113.10"}]


async def test_unconfigured_filter_drops_nothing(drive_consumer, monkeypatch):
    """With SENSOR_PUBLIC_IP unset (empty SELF_IPS) behaviour is unchanged —
    the guard must fail open, not swallow traffic."""
    monkeypatch.setattr(ingestor, "SELF_IPS", frozenset())
    pool, r = await drive_consumer([
        _suricata_alert("192.0.2.1", 21, "203.0.113.10", 57889),
    ])
    assert len(r.streams[ingestor.EVENTS_STREAM]) == 1


async def test_private_source_events_are_dropped(drive_consumer):
    """Probing the honeypot from the host arrives NAT'd as the Docker bridge
    gateway; one probe per service otherwise looks like a port sweep and shows
    up as a phantom row in scan correlation."""
    pool, r = await drive_consumer([
        _suricata_alert("172.21.0.1", 51000, "192.0.2.1", 2222),
        _suricata_alert("10.0.0.5", 51001, "192.0.2.1", 8080),
        _suricata_alert("127.0.0.1", 51002, "192.0.2.1", 6379),
        _suricata_alert("fe80::1", 51003, "192.0.2.1", 3306),
    ])
    assert pool.log == []
    assert r.streams == {}


async def test_documentation_ranges_are_not_treated_as_private(drive_consumer):
    """ipaddress.is_private covers TEST-NET (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24), which every fixture here uses for synthetic attackers.
    The filter must key off real private ranges only, or it guts the suite."""
    pool, r = await drive_consumer([
        _suricata_alert("203.0.113.10", 57889, "192.0.2.1", 21),
        _suricata_alert("198.51.100.5", 57890, "192.0.2.1", 21),
    ])
    assert len(r.streams[ingestor.EVENTS_STREAM]) == 2


async def test_private_filter_can_be_disabled(drive_consumer, monkeypatch):
    """An internal-segment deployment sets DROP_PRIVATE_SRC=0 and must get its
    RFC1918 traffic back."""
    monkeypatch.setattr(ingestor, "DROP_PRIVATE_SRC", False)
    pool, r = await drive_consumer([
        _suricata_alert("172.21.0.1", 51000, "192.0.2.1", 2222),
    ])
    assert len(r.streams[ingestor.EVENTS_STREAM]) == 1
