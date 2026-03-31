import responses as rsps
from ioc_enrich.enrichers.abuseipdb import AbuseIPDBEnricher
from ioc_enrich.models import IoCType

_ABUSEIPDB_RESPONSE = {
    "data": {
        "abuseConfidenceScore": 85,
        "totalReports": 42,
        "lastReportedAt": "2024-01-15T10:30:00+00:00",
        "isp": "LEVEL3",
        "usageType": "Data Center/Web Hosting/Transit",
        "countryCode": "US",
    }
}


@rsps.activate
def test_enrich_ip() -> None:
    rsps.add(rsps.GET, "https://api.abuseipdb.com/api/v2/check", json=_ABUSEIPDB_RESPONSE)
    enricher = AbuseIPDBEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert result.ioc == "1.2.3.4"
    assert result.abuse_confidence == 85
    assert result.total_reports == 42
    assert result.last_reported == "2024-01-15T10:30:00+00:00"
    assert result.isp == "LEVEL3"
    assert result.usage_type == "Data Center/Web Hosting/Transit"
    assert result.country == "US"
    assert result.error is None


def test_enrich_domain_returns_none() -> None:
    """AbuseIPDB only supports IPs; other types should be skipped silently."""
    enricher = AbuseIPDBEnricher("fake-key")
    assert enricher.enrich("example.com", IoCType.DOMAIN) is None


def test_enrich_hash_returns_none() -> None:
    enricher = AbuseIPDBEnricher("fake-key")
    assert enricher.enrich("d41d8cd98f00b204e9800998ecf8427e", IoCType.HASH) is None


@rsps.activate
def test_enrich_http_error() -> None:
    rsps.add(rsps.GET, "https://api.abuseipdb.com/api/v2/check", status=429, json={})
    enricher = AbuseIPDBEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert result.error is not None
    assert "429" in result.error


@rsps.activate
def test_enrich_missing_data_fields() -> None:
    """Partial responses should not crash; missing fields default to 0/None."""
    rsps.add(rsps.GET, "https://api.abuseipdb.com/api/v2/check", json={"data": {}})
    enricher = AbuseIPDBEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert result.abuse_confidence == 0
    assert result.total_reports == 0
    assert result.last_reported is None
    assert result.error is None
