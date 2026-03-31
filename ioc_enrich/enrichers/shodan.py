from __future__ import annotations

import requests

from ioc_enrich.models import IoCType, ShodanResult

_BASE = "https://api.shodan.io/shodan/host"


class ShodanEnricher:
    """Enriches IP addresses using the Shodan REST API.

    Only IPs are supported — calling enrich() on a domain, hash, or URL
    returns None silently so the CLI can skip it without special-casing.

    Free-tier Shodan accounts can query the /shodan/host/{ip} endpoint but
    do not include service banners in the response.  The enricher handles
    this gracefully by treating missing banner data as empty strings.
    """

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._session = requests.Session()

    def enrich(self, ioc: str, ioc_type: IoCType) -> ShodanResult | None:
        """Return a ShodanResult for an IP, or None for any other type."""
        if ioc_type is not IoCType.IP:
            # Shodan host lookups are IP-only; silently skip other types.
            return None
        try:
            return self._fetch(ioc)
        except requests.HTTPError as exc:
            code = exc.response.status_code
            if code == 404:
                # IP has never been scanned by Shodan — not an error.
                return ShodanResult(ioc=ioc, error="Not found in Shodan index")
            if code in (401, 403):
                # Free-tier accounts cannot access some IPs or endpoints.
                return ShodanResult(
                    ioc=ioc,
                    error="Unauthorised — API key invalid or free-tier restriction",
                )
            return ShodanResult(
                ioc=ioc,
                error=f"HTTP {code}: {exc.response.text[:200]}",
            )
        except requests.RequestException as exc:
            return ShodanResult(ioc=ioc, error=str(exc))

    def _fetch(self, ip: str) -> ShodanResult:
        resp = self._session.get(
            f"{_BASE}/{ip}",
            params={"key": self._api_key},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        # Each item in data["data"] is one open port / service banner.
        services: list[dict] = []
        for item in data.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product"),
                "version": item.get("version"),
                # Banners can be very long; trim to 200 chars for display.
                "banner": (item.get("data") or "").strip()[:200],
            })

        return ShodanResult(
            ioc=ip,
            ports=sorted(data.get("ports", [])),
            services=services,
            os=data.get("os"),
            org=data.get("org"),
            isp=data.get("isp"),
            country=data.get("country_name"),
            city=data.get("city"),
            last_update=data.get("last_update"),
        )
