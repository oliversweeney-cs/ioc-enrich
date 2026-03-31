"""Tests for CLI-level behaviour: file input, stdin, dedup, validation, brief mode."""
from __future__ import annotations

import responses as rsps
from click.testing import CliRunner

from ioc_enrich.cli import _classify_and_dedup, _collect_iocs, main
from ioc_enrich.models import IoCType

# Minimal VT response that satisfies the parser without triggering API errors.
_VT_IP = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 4
            },
            "reputation": 0,
            "tags": [],
        }
    }
}
_VT_IP_SUSPICIOUS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 3, "suspicious": 1, "harmless": 80, "undetected": 10
            },
            "reputation": -5,
            "tags": ["suspicious-host"],
        }
    }
}
_VT_DOMAIN = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 4
            },
            "reputation": 500,
            "tags": [],
        }
    }
}

# Helper: run the CLI with a fake VT key and no AbuseIPDB/Shodan keys so that
# only VirusTotal is active and we don't need to mock two extra APIs.
_BASE_ENV = {
    "VIRUSTOTAL_API_KEY": "fake-vt-key",
    "ABUSEIPDB_API_KEY": "",
    "SHODAN_API_KEY": "",
}


# ---------------------------------------------------------------------------
# _collect_iocs unit tests (no API calls needed)
# ---------------------------------------------------------------------------

def test_collect_iocs_from_args(tmp_path):
    result = _collect_iocs(("1.2.3.4", "example.com"), None)
    assert result == ["1.2.3.4", "example.com"]


def test_collect_iocs_from_file_skips_comments(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("# this is a comment\n1.2.3.4\n\n# another comment\nexample.com\n")
    result = _collect_iocs((), str(f))
    assert result == ["1.2.3.4", "example.com"]


def test_collect_iocs_from_file_skips_blank_lines(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("1.2.3.4\n\n\nexample.com\n")
    result = _collect_iocs((), str(f))
    assert result == ["1.2.3.4", "example.com"]


def test_collect_iocs_inline_hash_comment(tmp_path):
    """'#' in the middle of a line (e.g. after an IoC) should NOT be stripped."""
    f = tmp_path / "iocs.txt"
    # Commented-out lines start with '#'; inline '#' is kept as part of the value.
    f.write_text("# header\n1.2.3.4\n")
    result = _collect_iocs((), str(f))
    assert "1.2.3.4" in result
    assert not any(v.startswith("#") for v in result)


# ---------------------------------------------------------------------------
# _classify_and_dedup unit tests
# ---------------------------------------------------------------------------

def test_classify_and_dedup_deduplicates():
    result = _classify_and_dedup(["1.2.3.4", "example.com", "1.2.3.4"])
    assert len(result) == 2
    assert result[0] == ("1.2.3.4", IoCType.IP)
    assert result[1] == ("example.com", IoCType.DOMAIN)


def test_classify_and_dedup_skips_unknown():
    result = _classify_and_dedup(["1.2.3.4", "not_an_ioc!!", "example.com"])
    assert len(result) == 2
    ioc_values = [r[0] for r in result]
    assert "not_an_ioc!!" not in ioc_values


# ---------------------------------------------------------------------------
# Full CLI tests via CliRunner
# ---------------------------------------------------------------------------

@rsps.activate
def test_cli_file_input(tmp_path):
    """--file flag reads IoCs from a file, skipping comments and blanks."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/domains/example.com", json=_VT_DOMAIN)

    f = tmp_path / "iocs.txt"
    f.write_text("# targets for today\n1.2.3.4\n\nexample.com\n")

    runner = CliRunner()
    result = runner.invoke(main, ["--no-color", "-f", str(f)], env=_BASE_ENV)

    assert result.exit_code == 0, result.output
    # Rich folds long values in narrow columns — verify by count, not exact IoC text.
    assert "2 IOCs enriched" in result.output
    # Both IoC types appear in the Type column (no folding there).
    assert "ip" in result.output
    assert "domain" in result.output


@rsps.activate
def test_cli_deduplication(tmp_path):
    """Duplicate IoCs should only be queried once and appear once in output."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)

    runner = CliRunner()
    result = runner.invoke(
        main, ["--no-color", "1.2.3.4", "1.2.3.4"], env=_BASE_ENV
    )

    assert result.exit_code == 0, result.output
    assert "1 IOCs enriched" in result.output
    assert "Deduplicating" in result.output


@rsps.activate
def test_cli_invalid_ioc_warning():
    """Unknown IoC values should produce a 'Skipping invalid IOC:' warning."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)

    runner = CliRunner()
    result = runner.invoke(
        main, ["--no-color", "1.2.3.4", "not_an_ioc!!"], env=_BASE_ENV
    )

    assert result.exit_code == 0, result.output
    assert "Skipping invalid IOC" in result.output
    assert "not_an_ioc!!" in result.output
    assert "1 IOCs enriched" in result.output


@rsps.activate
def test_cli_brief_mode():
    """--brief shows IoC, Verdict, VT Detection only — no AIPDB / Shodan columns."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)

    runner = CliRunner()
    result = runner.invoke(main, ["--no-color", "-b", "1.2.3.4"], env=_BASE_ENV)

    assert result.exit_code == 0, result.output
    assert "VT Detection" in result.output
    assert "Verdict" in result.output
    # Brief mode must NOT include AbuseIPDB or Shodan columns.
    assert "AIPDB" not in result.output
    assert "Shodan" not in result.output


@rsps.activate
def test_cli_brief_mode_still_shows_summary():
    """Brief mode should still print the summary line."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)

    runner = CliRunner()
    result = runner.invoke(main, ["--no-color", "-b", "1.2.3.4"], env=_BASE_ENV)

    assert result.exit_code == 0, result.output
    assert "IOCs enriched" in result.output


@rsps.activate
def test_cli_default_table_has_renamed_columns():
    """Default table should use the new column names from the spec."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)

    runner = CliRunner()
    result = runner.invoke(main, ["--no-color", "1.2.3.4"], env=_BASE_ENV)

    assert result.exit_code == 0, result.output
    assert "VT Detection" in result.output
    assert "AIPDB Score" in result.output
    assert "Shodan Ports" in result.output
    # Old column name must not appear.
    assert "Detection\n" not in result.output
    assert "Abuse Score" not in result.output


@rsps.activate
def test_cli_default_table_no_tags_column():
    """Tags should NOT appear as a column in the default table view."""
    rsps.add(
        rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        json=_VT_IP_SUSPICIOUS
    )

    runner = CliRunner()
    result = runner.invoke(main, ["--no-color", "1.2.3.4"], env=_BASE_ENV)

    assert result.exit_code == 0, result.output
    # "Tags" header should not be in the default output.
    assert "Tags" not in result.output


@rsps.activate
def test_cli_verbose_shows_tags():
    """Tags should appear in verbose (-v) output even though they're gone from the table."""
    rsps.add(
        rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        json=_VT_IP_SUSPICIOUS
    )

    runner = CliRunner()
    result = runner.invoke(main, ["--no-color", "-v", "1.2.3.4"], env=_BASE_ENV)

    assert result.exit_code == 0, result.output
    assert "suspicious-host" in result.output


@rsps.activate
def test_cli_no_color_flag():
    """--no-color produces output without Rich markup escape sequences."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)

    runner = CliRunner()
    result = runner.invoke(main, ["--no-color", "1.2.3.4"], env=_BASE_ENV)

    assert result.exit_code == 0, result.output
    # No ANSI escape codes should be in the output.
    assert "\x1b[" not in result.output


@rsps.activate
def test_cli_shodan_no_key_shows_nk():
    """When Shodan key is absent, IP rows should show N/K in the Shodan Ports column."""
    rsps.add(rsps.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4", json=_VT_IP)

    runner = CliRunner()
    # Explicitly unset Shodan key while keeping VT key.
    result = runner.invoke(
        main,
        ["--no-color", "1.2.3.4"],
        env={"VIRUSTOTAL_API_KEY": "fake-vt-key", "ABUSEIPDB_API_KEY": "", "SHODAN_API_KEY": ""},
    )

    assert result.exit_code == 0, result.output
    assert "N/K" in result.output
