# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # then fill in VIRUSTOTAL_API_KEY
```

## Commands

```bash
# Run the CLI
ioc-enrich 1.2.3.4 example.com
ioc-enrich --output json 8.8.8.8
ioc-enrich --file iocs.txt
echo "1.2.3.4" | ioc-enrich

# Lint
ruff check .
ruff format .

# Tests
pytest                        # all tests
pytest tests/test_models.py   # single file
pytest -k test_enrich_ip      # single test by name
```

## Architecture

The tool is structured around three layers:

1. **`ioc_enrich/models.py`** — Core data types. `IoCType` enum, `detect_ioc_type()` for classifying raw strings, and `EnrichmentResult` dataclass that all enrichers return.

2. **`ioc_enrich/enrichers/`** — One module per threat intel source (currently `virustotal.py`). Each enricher takes an `(ioc, ioc_type)` pair and returns an `EnrichmentResult`. Errors are caught internally and surfaced via `result.error` rather than raised, so the CLI can continue processing the remaining IoCs.

3. **`ioc_enrich/cli.py`** — Click entrypoint. Collects IoCs from arguments, `--file`, or stdin; calls `detect_ioc_type` on each; dispatches to the enricher; renders as a Rich table or JSON.

## Adding a new enricher

1. Create `ioc_enrich/enrichers/<name>.py` with a class that exposes `enrich(ioc, ioc_type) -> <ResultType> | None`.
   - IP-only enrichers return `None` for non-IP types (silently skipped by the CLI).
   - All-type enrichers return their own result dataclass (e.g. `EnrichmentResult` for VT).
2. Add the result dataclass to `models.py` if the enricher has a unique schema (see `AbuseIPDBResult`, `ShodanResult`).
3. Add a field for the new result to `IoCBundle` in `models.py`.
4. Export the enricher from `ioc_enrich/enrichers/__init__.py`.
5. Add its API key env var to `.env.example` and document it in the env table above.
6. Wire it into `cli.py`: add a `--<name>-key` option, instantiate the enricher if the key is present, add the result to the bundle, and update `_render_table` / `_render_verbose` / `_render_csv`.

### Current enrichers

| Enricher | IoC types | Key env var | Rate limit |
|---|---|---|---|
| `VirusTotalEnricher` | IP, domain, hash, URL | `VIRUSTOTAL_API_KEY` | 4 req/min, 500/day |
| `AbuseIPDBEnricher` | IP only | `ABUSEIPDB_API_KEY` | 1,000 checks/day |
| `ShodanEnricher` | IP only | `SHODAN_API_KEY` | varies by plan |

## Environment variables

| Variable | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal API v3 key (required) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API v2 key (optional; IP-only) |
| `SHODAN_API_KEY` | Shodan REST API key (optional; IP-only) |

Loaded automatically from `.env` via `python-dotenv` at CLI startup.  AbuseIPDB and Shodan keys are optional — their enrichers are skipped silently if the key is absent.

## Coding conventions

- Target Python 3.11+ on Ubuntu 24.04
- Use `--break-system-packages` flag if installing packages outside the venv
- All CLI output uses Rich for formatting; no bare print() calls
- Error handling: catch exceptions per-IOC so batch runs don't abort on a single failure
- Rate limiting: respect VirusTotal free tier (4 requests/minute, 500/day)
- API keys must never be hardcoded; always read from environment or .env
- Keep external dependencies minimal; justify any new additions

## Verdict thresholds

- MALICIOUS: 5+ vendor detections on VirusTotal
- SUSPICIOUS: 1-4 vendor detections
- CLEAN: 0 detections
- UNKNOWN: IOC not found in VT database

These thresholds should be configurable via CLI flags.

## Project context

This tool is part of a SOC analyst training lab. The primary user is an intermediate cybersecurity student building practical tooling for alert triage and incident response workflows. Code should be well-commented to support learning.
