"""Unit tests evaluating the format detection engine against the entire golden corpus."""

import pytest

from logmorph.domain.uls import LogFormatEnum
from logmorph.engine.detector import detect_format
from tests.fixtures.loader import (
    get_fixture_path,
    get_fixtures_dir,
    load_fixture_lines,
    load_ground_truth_corpus,
)


def test_fixtures_directory_exists():
    """Verify that fixtures/logs directory exists on disk."""
    dir_path = get_fixtures_dir()
    assert dir_path.is_dir()


def test_fixture_loader_file_not_found():
    """Verify that non-existent fixture files raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        get_fixture_path("non_existent_fixture.log")


def test_golden_corpus_contains_all_formats():
    """Verify that all 7 LogFormatEnum formats have non-empty sample lists."""
    corpus = load_ground_truth_corpus()
    for fmt in LogFormatEnum:
        assert fmt in corpus, f"Format {fmt} missing from golden corpus"
        assert len(corpus[fmt]) > 0, f"Format {fmt} has 0 sample lines"


@pytest.mark.parametrize(
    "format_name,filename",
    [
        (LogFormatEnum.SYSLOG, "syslog_rfc5424.log"),
        (LogFormatEnum.SYSLOG, "syslog_rfc3164.log"),
        (LogFormatEnum.CLF, "apache_clf.log"),
        (LogFormatEnum.CEF, "cef_events.log"),
        (LogFormatEnum.LEEF, "leef_events.log"),
        (LogFormatEnum.JSON, "json_events.jsonl"),
        (LogFormatEnum.XML, "xml_events.log"),
        (LogFormatEnum.UNSTRUCTURED, "unstructured.log"),
    ],
)
def test_fixture_file_classification_accuracy(format_name: LogFormatEnum, filename: str):
    """Test that 100% of the lines in each fixture file match the expected format."""
    lines = load_fixture_lines(filename)
    assert len(lines) > 0, f"Fixture {filename} has no lines"

    for idx, line in enumerate(lines):
        result = detect_format(line)
        assert result.detected_format == format_name, (
            f"Classification mismatch in {filename} line {idx + 1}:\n"
            f"Line: {line}\n"
            f"Expected: {format_name}, Got: {result.detected_format} (confidence={result.confidence})"
        )
        assert result.confidence > 0.0, f"Confidence zero for {filename} line {idx + 1}"


def test_syslog_rfc5424_sub_format_hint():
    """Verify RFC 5424 lines receive the RFC_5424 sub-format descriptor."""
    lines = load_fixture_lines("syslog_rfc5424.log")
    for line in lines:
        result = detect_format(line)
        assert result.detected_format == LogFormatEnum.SYSLOG
        assert result.sub_format == "RFC_5424"


def test_apache_clf_sub_format_hints():
    """Verify Apache lines receive either COMMON or COMBINED sub-format descriptors."""
    lines = load_fixture_lines("apache_clf.log")
    for line in lines:
        result = detect_format(line)
        assert result.detected_format == LogFormatEnum.CLF
        assert result.sub_format in ("COMMON", "COMBINED")
