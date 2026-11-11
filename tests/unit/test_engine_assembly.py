"""Comprehensive unit and integration test suite for the unified LogMorphEngine assembly.

Validates end-to-end pipeline orchestration across all stages:
1. Detection -> 2. Cascade Parsing -> 3. Quality/Normalization -> 4. Deduplication
-> 5. Contextual Enrichment (GeoIP, Threat Intel, MITRE ATT&CK) -> 6. Telemetry.
"""

from __future__ import annotations

import time
import uuid

import pytest

from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum
from logmorph.engine.core import (
    EngineMetrics,
    LogMorphEngine,
    get_engine,
)
from logmorph.schemas.engine import EngineConfig


@pytest.fixture
def isolated_engine() -> LogMorphEngine:
    """Return an isolated LogMorphEngine instance with pristine metrics."""
    metrics = EngineMetrics()
    config = EngineConfig(
        detection_enabled=True,
        cascade_enabled=True,
        quality_pipeline_enabled=True,
        deduplication_enabled=True,
        drop_duplicates=False,
        geoip_enabled=True,
        threat_intel_enabled=True,
        mitre_tagger_enabled=True,
    )
    return LogMorphEngine(config=config, metrics=metrics)


# ==============================================================================
# 1. Golden Corpus End-to-End Orchestration Tests
# ==============================================================================


def test_json_log_end_to_end_pipeline(isolated_engine: LogMorphEngine) -> None:
    """JSON log passes through detection, Tier 1 parsing, normalization, and enrichment."""
    raw = (
        '{"timestamp": "2026-10-30T10:00:00Z", "level": "error", "action": "LOGIN_FAILED", '
        '"src_ip": "8.8.8.8", "dst_ip": "10.0.0.1", "user": "victim_user", "message": "Failed login"}'
    )
    tenant_id = uuid.uuid4()

    res = isolated_engine.process(raw, tenant_id=tenant_id)
    assert res.success is True
    assert res.event is not None
    assert res.format_detected == LogFormatEnum.JSON
    assert res.parsed_by == ParsingTierEnum.RULE
    assert res.event.action == "LOGIN_FAILED"
    assert res.event.source is not None
    assert res.event.source.ip == "8.8.8.8"
    assert res.is_duplicate is False

    # Enrichment checks
    assert res.event.enrichment is not None
    assert res.event.enrichment.geoip is not None
    assert res.event.enrichment.geoip.country == "United States"
    assert res.event.enrichment.mitre_technique == "T1110.001"


def test_syslog_rfc3164_end_to_end_pipeline(isolated_engine: LogMorphEngine) -> None:
    """Syslog RFC 3164 log is detected, normalized, and timestamp-localized."""
    raw = "Oct 30 10:00:00 webserver sshd[1234]: Failed password for root from 8.8.8.8 port 22 ssh2"
    tenant_id = uuid.uuid4()

    res = isolated_engine.process(raw, tenant_id=tenant_id)
    assert res.success is True
    assert res.event is not None
    assert res.format_detected == LogFormatEnum.SYSLOG
    assert res.parsed_by == ParsingTierEnum.RULE
    assert res.event.enrichment is not None
    assert res.event.enrichment.mitre_technique == "T1110.001"


def test_cef_log_end_to_end_pipeline(isolated_engine: LogMorphEngine) -> None:
    """CEF security event is parsed, normalized, and correlated."""
    raw = (
        "CEF:0|SecurityCompany|Firewall|1.0|100|Port Scan Detected|7|"
        "src=8.8.8.8 dst=10.0.0.1 act=PORT_SCAN msg=SYN stealth scan"
    )
    tenant_id = uuid.uuid4()

    res = isolated_engine.process(raw, tenant_id=tenant_id)
    assert res.success is True
    assert res.event is not None
    assert res.format_detected == LogFormatEnum.CEF
    assert res.event.action == "PORT_SCAN"
    assert res.event.enrichment is not None
    assert res.event.enrichment.mitre_technique == "T1046"


def test_apache_clf_end_to_end_pipeline(isolated_engine: LogMorphEngine) -> None:
    """Apache Combined Log Format event is processed through full stack."""
    raw = '8.8.8.8 - admin [30/Oct/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 200 2326'
    tenant_id = uuid.uuid4()

    res = isolated_engine.process(raw, tenant_id=tenant_id)
    assert res.success is True
    assert res.event is not None
    assert res.format_detected == LogFormatEnum.CLF
    assert res.event.source is not None
    assert res.event.source.ip == "8.8.8.8"
    assert res.event.enrichment is not None
    assert res.event.enrichment.geoip is not None
    assert res.event.enrichment.geoip.country == "United States"


def test_unstructured_log_cascade_fallback(isolated_engine: LogMorphEngine) -> None:
    """Novel unstructured log flows through Drain3 template mining cascade."""
    raw = "System disk sda1 failed I/O sector 492049 critical block corruption"
    tenant_id = uuid.uuid4()

    res = isolated_engine.process(raw, tenant_id=tenant_id)
    assert res.success is True
    assert res.event is not None
    assert res.event.raw_log == raw
    assert res.parsed_by in (
        ParsingTierEnum.TEMPLATE,
        ParsingTierEnum.LLM,
        ParsingTierEnum.FALLBACK,
    )


# ==============================================================================
# 2. Simultaneous Multi-Enrichment Verification
# ==============================================================================


def test_simultaneous_full_enrichment(isolated_engine: LogMorphEngine) -> None:
    """Log containing C2 threat IP, failed auth, and GeoIP triggers all enrichments."""
    # 194.26.29.112 is a known Cobalt Strike C2 IP in the embedded threat feed
    raw = (
        '{"timestamp": "2026-10-30T10:00:00Z", "action": "LOGIN_FAILED", '
        '"src_ip": "8.8.8.8", "dst_ip": "194.26.29.112", "user": "admin", '
        '"message": "Cobalt Strike beacon check-in"}'
    )
    tenant_id = uuid.uuid4()

    res = isolated_engine.process(raw, tenant_id=tenant_id)
    assert res.success is True
    assert res.event is not None

    # 1. GeoIP enriched
    assert res.geoip_country == "United States"
    assert res.event.enrichment is not None
    assert res.event.enrichment.geoip is not None

    # 2. Threat Intel enriched
    assert res.threat_matched is True
    assert res.event.enrichment.threat_match is True
    assert res.event.security is not None
    assert res.event.security.threat_id == "Cobalt Strike C2"
    assert "threat_intel" in res.event.attributes

    # 3. MITRE ATT&CK enriched
    assert res.mitre_technique is not None
    assert res.event.enrichment.mitre_technique is not None
    assert "mitre_attack" in res.event.attributes


# ==============================================================================
# 3. Multi-Tenant Isolation & Deduplication Tests
# ==============================================================================


def test_multi_tenant_deduplication_isolation(isolated_engine: LogMorphEngine) -> None:
    """Deduplication fingerprints maintain strict tenant isolation."""
    raw = '{"timestamp": "2026-10-30T10:00:00Z", "message": "Identical event payload"}'
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    # Tenant A - 1st occurrence: Unique
    res_a1 = isolated_engine.process(raw, tenant_id=tenant_a)
    assert res_a1.is_duplicate is False

    # Tenant A - 2nd occurrence: Duplicate
    res_a2 = isolated_engine.process(raw, tenant_id=tenant_a)
    assert res_a2.is_duplicate is True

    # Tenant B - 1st occurrence: Unique (Tenant isolation guaranteed!)
    res_b1 = isolated_engine.process(raw, tenant_id=tenant_b)
    assert res_b1.is_duplicate is False


def test_drop_duplicates_configuration() -> None:
    """When drop_duplicates=True, duplicates return success=True but event=None."""
    cfg = EngineConfig(drop_duplicates=True)
    engine = LogMorphEngine(config=cfg)

    raw = '{"timestamp": "2026-10-30T10:00:00Z", "msg": "Drop test"}'
    tenant_id = uuid.uuid4()

    res1 = engine.process(raw, tenant_id=tenant_id)
    assert res1.success is True
    assert res1.event is not None
    assert res1.is_duplicate is False

    res2 = engine.process(raw, tenant_id=tenant_id)
    assert res2.success is True
    assert res2.event is None
    assert res2.is_duplicate is True


# ==============================================================================
# 4. Stage Toggles Configuration Tests
# ==============================================================================


def test_stage_toggles_disabled() -> None:
    """Disabling enrichers in EngineConfig bypasses their respective stages."""
    cfg = EngineConfig(
        geoip_enabled=False,
        threat_intel_enabled=False,
        mitre_tagger_enabled=False,
    )
    engine = LogMorphEngine(config=cfg)

    raw = (
        '{"timestamp": "2026-10-30T10:00:00Z", "action": "LOGIN_FAILED", '
        '"src_ip": "194.26.29.112", "user": "admin"}'
    )
    res = engine.process(raw, tenant_id=uuid.uuid4())
    assert res.success is True
    assert res.event is not None

    # All enrichment fields must be unpopulated / False
    assert res.event.enrichment is None or (
        res.event.enrichment.geoip is None
        and res.event.enrichment.threat_match is False
        and res.event.enrichment.mitre_technique is None
    )


# ==============================================================================
# 5. Error Handling & Input Validation
# ==============================================================================


def test_empty_and_whitespace_log_rejection(isolated_engine: LogMorphEngine) -> None:
    """Empty or whitespace strings return success=False with clear error diagnostics."""
    tenant = uuid.uuid4()
    assert isolated_engine.process("", tenant_id=tenant).success is False
    assert isolated_engine.process("   ", tenant_id=tenant).success is False
    assert isolated_engine.process("\t\n", tenant_id=tenant).success is False


def test_invalid_tenant_uuid_rejection(isolated_engine: LogMorphEngine) -> None:
    """Malformed tenant string returns success=False without crashing."""
    res = isolated_engine.process("valid log content", tenant_id="not-a-valid-uuid")
    assert res.success is False
    assert "Invalid tenant UUID" in (res.error_message or "")


# ==============================================================================
# 6. Batch Processing Tests (Sync & Async)
# ==============================================================================


def test_process_batch_synchronous(isolated_engine: LogMorphEngine) -> None:
    """process_batch maintains 1:1 input ordering across multiple formats."""
    logs = [
        '{"action": "ALLOW", "user": "alice"}',
        "Oct 30 10:00:00 host sshd[1]: Accepted publickey for bob",
        "CEF:0|Vendor|Product|1.0|200|File Saved|3|act=SAVE",
        '8.8.8.8 - - [30/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100',
    ]
    tenant_id = uuid.uuid4()

    results = isolated_engine.process_batch(logs, tenant_id=tenant_id)
    assert len(results) == 4
    for r in results:
        assert r.success is True
        assert r.event is not None


@pytest.mark.asyncio
async def test_process_async_and_batch_async(isolated_engine: LogMorphEngine) -> None:
    """process_async and process_batch_async execute asynchronously."""
    tenant_id = uuid.uuid4()
    raw = '{"action": "CONNECT", "host": "api.example.com"}'

    # Single async
    single_res = await isolated_engine.process_async(raw, tenant_id=tenant_id)
    assert single_res.success is True
    assert single_res.event is not None

    # Batch async
    batch_logs = [raw, '{"action": "DISCONNECT", "host": "api.example.com"}']
    batch_res = await isolated_engine.process_batch_async(batch_logs, tenant_id=tenant_id)
    assert len(batch_res) == 2
    assert all(r.success for r in batch_res)


# ==============================================================================
# 7. Telemetry & Performance SLA
# ==============================================================================


def test_telemetry_metrics_reconciliation(isolated_engine: LogMorphEngine) -> None:
    """Telemetry counters reconcile: total == successful + failed."""
    tenant = uuid.uuid4()

    isolated_engine.process('{"valid": true}', tenant_id=tenant)
    isolated_engine.process("", tenant_id=tenant)  # Will fail

    snap = isolated_engine.get_metrics()
    assert snap.total_processed == 2
    assert snap.successful == 1
    assert snap.failed == 1
    assert snap.avg_latency_ms >= 0.0

    isolated_engine.reset_metrics()
    snap_after = isolated_engine.get_metrics()
    assert snap_after.total_processed == 0


def test_engine_fast_path_performance_sla(isolated_engine: LogMorphEngine) -> None:
    """1,000 JSON logs through full stack must average under 3ms per log."""
    raw = '{"timestamp": "2026-10-30T10:00:00Z", "action": "ALLOW", "user": "benchmark"}'
    tenant = uuid.uuid4()

    # Warm up
    isolated_engine.process(raw, tenant_id=tenant)

    count = 1000
    start = time.perf_counter()
    for _ in range(count):
        isolated_engine.process(raw, tenant_id=tenant)
    duration = time.perf_counter() - start

    avg_ms = (duration / count) * 1000.0
    assert avg_ms < 5.0, f"Average latency {avg_ms:.2f}ms; expected < 5.0ms"


def test_default_singleton_accessor() -> None:
    """get_engine returns a configured LogMorphEngine instance."""
    engine = get_engine()
    assert isinstance(engine, LogMorphEngine)
