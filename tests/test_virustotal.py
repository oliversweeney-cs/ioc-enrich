import responses as rsps
import pytest
from ioc_enrich.enrichers.virustotal import VirusTotalEnricher
from ioc_enrich.models import IoCType

_VT_IP_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 50, "undetected": 10},
            "reputation": -5,
            "tags": ["malware"],
        }
    }
}


@rsps.activate
def test_enrich_ip() -> None:
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP_RESPONSE)
    enricher = VirusTotalEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result.ioc == "1.2.3.4"
    assert result.malicious == 3
    assert result.suspicious == 1
    assert result.reputation == -5
    assert result.tags == ["malware"]
    assert result.error is None


@rsps.activate
def test_enrich_http_error() -> None:
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", status=403, json={"error": {"code": "ForbiddenError"}})
    enricher = VirusTotalEnricher("bad-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result.error is not None
    assert "403" in result.error
