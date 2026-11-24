"""Typed fixture loader utilities for golden log datasets."""

from pathlib import Path

from logmorph.domain.uls import LogFormatEnum

FIXTURES_DIR = Path(__file__).parent / "logs"


def get_fixtures_dir() -> Path:
    """Return the absolute path to the fixtures/logs directory."""
    return FIXTURES_DIR


def get_fixture_path(filename: str) -> Path:
    """Return the absolute path to a specific fixture log file."""
    path = FIXTURES_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Fixture file not found: {path}")
    return path


def load_fixture_lines(filename: str) -> list[str]:
    """Load non-empty lines from a fixture file, stripping trailing whitespace."""
    file_path = get_fixture_path(filename)
    with file_path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def load_ground_truth_corpus() -> dict[LogFormatEnum, list[str]]:
    """Return a mapping of LogFormatEnum to ground-truth log sample strings."""
    return {
        LogFormatEnum.SYSLOG: (
            load_fixture_lines("syslog_rfc5424.log")
            + load_fixture_lines("syslog_rfc3164.log")
        ),
        LogFormatEnum.CLF: load_fixture_lines("apache_clf.log"),
        LogFormatEnum.CEF: load_fixture_lines("cef_events.log"),
        LogFormatEnum.LEEF: load_fixture_lines("leef_events.log"),
        LogFormatEnum.JSON: load_fixture_lines("json_events.jsonl"),
        LogFormatEnum.XML: load_fixture_lines("xml_events.log"),
        LogFormatEnum.UNSTRUCTURED: load_fixture_lines("unstructured.log"),
    }
