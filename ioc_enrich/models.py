from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class IoCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    UNKNOWN = "unknown"


_RE_IPV4 = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(value: str) -> IoCType:
    v = value.strip()
    if _RE_URL.match(v):
        return IoCType.URL
    if _RE_IPV4.match(v):
        return IoCType.IP
    if _RE_MD5.match(v) or _RE_SHA1.match(v) or _RE_SHA256.match(v):
        return IoCType.HASH
    if _RE_DOMAIN.match(v):
        return IoCType.DOMAIN
    return IoCType.UNKNOWN


# ---------------------------------------------------------------------------
# Per-source result types
# ---------------------------------------------------------------------------

@dataclass
class EnrichmentResult:
    """VirusTotal enrichment result.  One instance per IoC."""
    ioc: str
    ioc_type: IoCType
    source: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_vendors: int = 0          # total number of vendors that scanned this IoC
    reputation: int | None = None
    tags: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)   # type-specific verbose fields (ASN, registrar, etc.)
    error: str | None = None


@dataclass
class AbuseIPDBResult:
    """AbuseIPDB enrichment result.  IP addresses only."""
    ioc: str
    abuse_confidence: int = 0       # 0–100 confidence score
    total_reports: int = 0          # number of distinct abuse reports
    last_reported: str | None = None  # ISO-8601 datetime string from the API
    isp: str | None = None
    usage_type: str | None = None   # e.g. "Data Center/Web Hosting/Transit"
    country: str | None = None      # two-letter country code
    error: str | None = None


@dataclass
class ShodanResult:
    """Shodan enrichment result.  IP addresses only."""
    ioc: str
    ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)  # [{port, transport, product, version, banner}]
    os: str | None = None
    org: str | None = None
    isp: str | None = None
    country: str | None = None
    city: str | None = None
    last_update: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Aggregated view
# ---------------------------------------------------------------------------

@dataclass
class IoCBundle:
    """Aggregates enrichment results from all active sources for a single IoC.

    The CLI builds one IoCBundle per deduplicated IoC and renders the table
    from these bundles so that every row combines data from VT, AbuseIPDB,
    and Shodan in one place.
    """
    ioc: str
    ioc_type: IoCType
    vt: EnrichmentResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    # Tracks whether the Shodan key was configured so the display layer can
    # distinguish "no key" (N/K) from "not indexed by Shodan" (N/A).
    shodan_key_present: bool = True
