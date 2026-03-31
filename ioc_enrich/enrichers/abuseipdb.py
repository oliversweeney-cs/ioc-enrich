from __future__ import annotations

import requests

from ioc_enrich.models import AbuseIPDBResult, IoCType

_BASE = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher:
    """Enriches IP addresses using the AbuseIPDB API v2.

    Only IPs are supported — calling enrich() on a domain, hash, or URL
    returns None silently so the CLI can skip it without special-casing.

    Rate limit on the free tier: 1,000 checks/day.  No per-minute cap.
    """

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self._timeout = timeout
        self._session = requests.Session()
        # AbuseIPDB expects the key in the "Key" header plus Accept JSON.
        self._session.headers.update({"Key": api_key, "Accept": "application/json"})

    def enrich(self, ioc: str, ioc_type: IoCType) -> AbuseIPDBResult | None:
        """Return an AbuseIPDBResult for an IP, or None for any other type."""
        if ioc_type is not IoCType.IP:
            # AbuseIPDB only supports IPs; silently skip other types.
            return None
        try:
            return self._fetch(ioc)
        except requests.HTTPError as exc:
            return AbuseIPDBResult(
                ioc=ioc,
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except requests.RequestException as exc:
            return AbuseIPDBResult(ioc=ioc, error=str(exc))

    def _fetch(self, ip: str) -> AbuseIPDBResult:
        resp = self._session.get(
            _BASE,
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,  # look back 90 days for reports
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        return AbuseIPDBResult(
            ioc=ip,
            abuse_confidence=data.get("abuseConfidenceScore", 0),
            total_reports=data.get("totalReports", 0),
            last_reported=data.get("lastReportedAt"),
            isp=data.get("isp"),
            usage_type=data.get("usageType"),
            country=data.get("countryCode"),
        )
