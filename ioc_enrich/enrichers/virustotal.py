from __future__ import annotations

import base64
from datetime import datetime, timezone

import requests

from ioc_enrich.models import EnrichmentResult, IoCType

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalEnricher:
    """Enriches IoCs using the VirusTotal API v3."""

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"x-apikey": api_key})

    def enrich(self, ioc: str, ioc_type: IoCType) -> EnrichmentResult:
        try:
            return self._dispatch(ioc, ioc_type)
        except requests.HTTPError as exc:
            return EnrichmentResult(
                ioc=ioc,
                ioc_type=ioc_type,
                source="virustotal",
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except requests.RequestException as exc:
            return EnrichmentResult(ioc=ioc, ioc_type=ioc_type, source="virustotal", error=str(exc))

    def _dispatch(self, ioc: str, ioc_type: IoCType) -> EnrichmentResult:
        match ioc_type:
            case IoCType.IP:
                url = f"{_BASE}/ip_addresses/{ioc}"
            case IoCType.DOMAIN:
                url = f"{_BASE}/domains/{ioc}"
            case IoCType.HASH:
                url = f"{_BASE}/files/{ioc}"
            case IoCType.URL:
                encoded = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
                url = f"{_BASE}/urls/{encoded}"
            case _:
                return EnrichmentResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    source="virustotal",
                    error="Unsupported IoC type",
                )

        resp = self._session.get(url, timeout=self._timeout)
        resp.raise_for_status()
        return self._parse(ioc, ioc_type, resp.json())

    def _parse(self, ioc: str, ioc_type: IoCType, data: dict) -> EnrichmentResult:
        attrs = data.get("data", {}).get("attributes", {})
        stats: dict = attrs.get("last_analysis_stats", {})
        tags: list[str] = attrs.get("tags", [])
        reputation: int | None = attrs.get("reputation")

        # Sum all vendor scan categories to get the total vendor count for the X/Y detection ratio.
        total_vendors = sum(stats.values())

        # Collect type-specific fields surfaced when the user passes --verbose.
        extra: dict = {}
        if ioc_type is IoCType.IP:
            extra = {
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "network": attrs.get("network"),
            }
        elif ioc_type is IoCType.DOMAIN:
            # VT returns creation_date as a Unix timestamp integer.
            creation_ts = attrs.get("creation_date")
            creation_date = (
                datetime.fromtimestamp(creation_ts, tz=timezone.utc).strftime("%Y-%m-%d")
                if creation_ts
                else None
            )
            extra = {
                "registrar": attrs.get("registrar"),
                "creation_date": creation_date,
                "last_dns_records": attrs.get("last_dns_records", []),
            }
        elif ioc_type is IoCType.HASH:
            extra = {
                "type_description": attrs.get("type_description"),
                "size": attrs.get("size"),
                "meaningful_name": attrs.get("meaningful_name"),
                "signature_info": attrs.get("signature_info", {}),
            }

        return EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            source="virustotal",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_vendors=total_vendors,
            reputation=reputation,
            tags=tags,
            extra=extra,
        )
