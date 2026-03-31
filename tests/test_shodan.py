import responses as rsps
from ioc_enrich.enrichers.shodan import ShodanEnricher
from ioc_enrich.models import IoCType

_SHODAN_RESPONSE = {
    "ports": [22, 80, 443],
    "data": [
        {
            "port": 22,
            "transport": "tcp",
            "product": "OpenSSH",
            "version": "8.9p1",
            "data": "SSH-2.0-OpenSSH_8.9p1",
        },
        {
            "port": 80,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.24.0",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx",
        },
    ],
    "os": "Linux",
    "org": "LEVEL3",
    "isp": "Level 3 Communications",
    "country_name": "United States",
    "city": "Chicago",
    "last_update": "2024-01-15T10:30:00.000000",
}


@rsps.activate
def test_enrich_ip() -> None:
    rsps.add(rsps.GET, "https://api.shodan.io/shodan/host/1.2.3.4", json=_SHODAN_RESPONSE)
    enricher = ShodanEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert result.ioc == "1.2.3.4"
    assert result.ports == [22, 80, 443]
    assert len(result.services) == 2
    assert result.services[0]["product"] == "OpenSSH"
    assert result.os == "Linux"
    assert result.org == "LEVEL3"
    assert result.country == "United States"
    assert result.city == "Chicago"
    assert result.last_update == "2024-01-15T10:30:00.000000"
    assert result.error is None


def test_enrich_domain_returns_none() -> None:
    """Shodan only supports IPs; other types should be skipped silently."""
    enricher = ShodanEnricher("fake-key")
    assert enricher.enrich("example.com", IoCType.DOMAIN) is None


def test_enrich_hash_returns_none() -> None:
    enricher = ShodanEnricher("fake-key")
    assert enricher.enrich("d41d8cd98f00b204e9800998ecf8427e", IoCType.HASH) is None


@rsps.activate
def test_enrich_404_not_found() -> None:
    """404 means the IP has never been scanned — should surface as error message, not crash."""
    rsps.add(rsps.GET, "https://api.shodan.io/shodan/host/1.2.3.4", status=404, json={})
    enricher = ShodanEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert result.error is not None
    assert "Not found" in result.error


@rsps.activate
def test_enrich_401_unauthorised() -> None:
    """401/403 from Shodan should produce a clear message about API key / free-tier limits."""
    rsps.add(rsps.GET, "https://api.shodan.io/shodan/host/1.2.3.4", status=401, json={})
    enricher = ShodanEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert result.error is not None
    assert "Unauthorised" in result.error


@rsps.activate
def test_enrich_empty_ports() -> None:
    """Response with no open ports should not crash."""
    rsps.add(
        rsps.GET,
        "https://api.shodan.io/shodan/host/1.2.3.4",
        json={"ports": [], "data": [], "org": "Test Org"},
    )
    enricher = ShodanEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert result.ports == []
    assert result.services == []
    assert result.org == "Test Org"
    assert result.error is None


@rsps.activate
def test_banner_trimmed_to_200_chars() -> None:
    """Long service banners must be trimmed so they don't flood the display."""
    long_banner = "X" * 500
    rsps.add(
        rsps.GET,
        "https://api.shodan.io/shodan/host/1.2.3.4",
        json={
            "ports": [9999],
            "data": [{"port": 9999, "transport": "tcp", "data": long_banner}],
        },
    )
    enricher = ShodanEnricher("fake-key")
    result = enricher.enrich("1.2.3.4", IoCType.IP)

    assert result is not None
    assert len(result.services[0]["banner"]) == 200
