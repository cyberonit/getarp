"""NUL sanitizing for provider data.

Provider responses are third-party data: org/hostname/category strings can be
derived from attacker-influenced rDNS or WHOIS, and the entire payload is stored
in ip_enrichment.raw (JSONB). Postgres accepts NUL (U+0000) in neither text nor
jsonb, and worker.consume() catches the failure, logs it and ACKs the message —
so an unsanitized NUL leaves that IP permanently unenriched (no country, no ASN,
no is_known_attacker) rather than raising anything visible.
"""
import json

from base import Enrichment, NUL_REPLACEMENT, _strip_nulls


def test_strip_nulls_recurses_through_provider_payloads():
    dirty = {
        "org": "Evil\x00Corp",
        "confidence": 0.9,
        "flagged": True,
        "missing": None,
        "categories": ["scan\x00ner", "bot"],
        "raw": {"whois": {"netname": "A\x00B"}, "hits": [1, "c\x00d"]},
    }
    clean = _strip_nulls(dirty)
    assert clean["org"] == f"Evil{NUL_REPLACEMENT}Corp"
    assert clean["categories"][0] == f"scan{NUL_REPLACEMENT}ner"
    assert clean["raw"]["whois"]["netname"] == f"A{NUL_REPLACEMENT}B"
    assert clean["raw"]["hits"][1] == f"c{NUL_REPLACEMENT}d"
    # non-strings must survive untouched — they are bound as real column types
    assert clean["confidence"] == 0.9
    assert clean["flagged"] is True
    assert clean["missing"] is None
    assert clean["categories"][1] == "bot"
    assert clean["raw"]["hits"][0] == 1


def test_as_db_sanitizes_every_field():
    """The dataclass -> DB boundary is the seam, so no provider can bypass it."""
    enr = Enrichment(
        src_ip="203.0.113.5", provider="tiered",
        country="N\x00L", asn="AS1\x00234", org="Evil\x00Corp",
        reputation="malicious", confidence=0.8,
        categories=["scan\x00ner"], is_known_attacker=True,
        raw={"nested": {"note": "x\x00y"}},
    )
    d = enr.as_db()
    for key in ("country", "asn", "org"):
        assert "\x00" not in d[key]
    assert "\x00" not in d["categories"][0]
    assert "\x00" not in json.dumps(d["raw"])
    assert "\\u0000" not in json.dumps(d["raw"])
    # untouched fields keep their exact values/types
    assert d["confidence"] == 0.8 and d["is_known_attacker"] is True
    assert d["src_ip"] == "203.0.113.5" and d["reputation"] == "malicious"


def test_clean_enrichment_is_unchanged():
    enr = Enrichment(src_ip="203.0.113.6", provider="tiered", country="NL",
                     org="Ordinary ISP", categories=["scanner"])
    d = enr.as_db()
    assert d["country"] == "NL"
    assert d["org"] == "Ordinary ISP"
    assert d["categories"] == ["scanner"]
    assert NUL_REPLACEMENT not in json.dumps(d)


async def test_nul_bearing_enrichment_actually_stores(pool):
    """The point of the fix: against a real Postgres, a provider response with
    NULs must persist instead of failing the upsert and dropping the IP."""
    import worker

    ip = "203.0.113.77"
    async with pool.acquire() as con:
        await con.execute("INSERT INTO ips (src_ip) VALUES ($1) "
                          "ON CONFLICT DO NOTHING", ip)

    enr = Enrichment(
        src_ip=ip, provider="tiered", country="N\x00L", asn="AS64500",
        org="Attacker\x00Controlled rDNS", reputation="malicious",
        confidence=0.95, categories=["c2\x00"], is_known_attacker=True,
        raw={"provider_said": "binary\x00junk", "deep": {"k": "v\x00"}},
    )
    await worker.upsert(pool, enr)   # must not raise

    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT country, asn, org, categories, is_known_attacker, raw "
            "FROM ip_enrichment WHERE src_ip=$1", ip)
    assert row is not None, "upsert silently stored nothing"
    assert row["country"] == f"N{NUL_REPLACEMENT}L"
    assert row["org"].startswith(f"Attacker{NUL_REPLACEMENT}Controlled")
    assert row["categories"] == [f"c2{NUL_REPLACEMENT}"]
    assert row["is_known_attacker"] is True
    assert row["asn"] == "AS64500"          # clean field untouched
    stored_raw = json.loads(row["raw"])
    assert stored_raw["provider_said"] == f"binary{NUL_REPLACEMENT}junk"
    assert stored_raw["deep"]["k"] == f"v{NUL_REPLACEMENT}"
