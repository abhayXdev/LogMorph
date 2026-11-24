"""Unit tests for Tier 2 Drain3 Template Mining Engine with Multi-Tenant Clustering.

Tests cover:
1. Template mining & clustering across varying parameters on unstructured.log
2. Parameter extraction and masked parameter correctness (PORT variants, NUM separation)
3. IPv6 masking (full, compressed ::1, fe80::1, negative cases like timestamps, MACs)
4. Severity inference across all keywords (NullPointerException, ERROR, FATAL, timed out, oom-killer, WARN)
5. Confidence precedence (generalized template with cluster_size >= 2 gets 0.75, not 0.90)
6. Malformed/empty input (confidence=0.10, success=False, should_route_to_llm=False)
7. Eviction correctness (pool past max_active_tenants flushes before eviction)
8. Cold start (is_loaded gate prevents premature evaluation)
9. Multi-tenant isolation (Tenant A templates never appear in Tenant B)
10. Concurrency under concurrent coroutines on the same tenant
11. Persistence round-trip (save/load state)
12. Dry-run path (inspect_tier2 never calls save_state or mutates clusters)
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum, SeverityEnum
from logmorph.engine.parsers.drain_miner import (
    AsyncTenantMinerPool,
    DrainTemplateMiner,
    ValidatedIPv6MaskingInstruction,
    infer_severity,
    inspect_tier2,
    parse_tier2,
    parse_tier2_async,
    should_route_to_llm,
)


# -------------------------------------------------------------------------
# 1. Template mining & clustering on unstructured fixture
# -------------------------------------------------------------------------
def test_unstructured_fixture_template_mining() -> None:
    """Test clustering and template mining on realistic unstructured logs."""
    fixture_path = Path("tests/fixtures/logs/unstructured.log")
    assert fixture_path.exists(), f"Fixture missing at {fixture_path}"

    lines = [line.strip() for line in fixture_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 5

    miner = DrainTemplateMiner(redis_enabled=False)
    tenant_id = str(uuid4())

    results = [miner.parse(line, tenant_id=tenant_id) for line in lines]

    for res in results:
        assert res.success is True
        assert res.format == LogFormatEnum.UNSTRUCTURED
        assert res.parsed_by == ParsingTierEnum.TEMPLATE
        assert res.confidence >= 0.50
        assert res.attributes is not None
        assert "template" in res.attributes
        assert "cluster_id" in res.attributes

    # Feed repeated variant of line 1 (NullPointerException at different line number)
    var_log = (
        'java.lang.NullPointerException: Cannot invoke "String.length()" '
        'because "str" is null at com.example.service.UserService.getUser(UserService.java:108)'
    )
    res_var = miner.parse(var_log, tenant_id=tenant_id)
    assert res_var.success is True
    assert res_var.attributes["cluster_size"] >= 2


# -------------------------------------------------------------------------
# 2. Parameter extraction and masked parameter correctness
# -------------------------------------------------------------------------
def test_parameter_extraction_and_port_variants() -> None:
    """Test parameter extraction, masks (IP, PORT, UUID, HEX, TIMESTAMP, EMAIL), and NUM separation."""
    miner = DrainTemplateMiner(redis_enabled=False)
    tid = str(uuid4())

    log_line = (
        "2026-10-30T10:15:30Z user sec_admin@corp.internal from 192.168.1.100 port 8080 "
        "session 123e4567-e89b-12d3-a456-426614174000 code 0xDEADBEEF processed 42 items"
    )

    result = miner.parse(log_line, tenant_id=tid)
    assert result.success is True
    attrs = result.attributes
    assert attrs is not None

    masked = attrs["masked_parameters"]
    assert masked.get("TIMESTAMP") == "2026-10-30T10:15:30Z"
    assert masked.get("EMAIL") == "sec_admin@corp.internal"
    assert masked.get("IP") == "192.168.1.100"
    assert masked.get("PORT") == "8080"
    assert masked.get("UUID") == "123e4567-e89b-12d3-a456-426614174000"
    assert masked.get("HEX") == "0xDEADBEEF"

    # Feed a second log with varying numeric count to trigger template generalization to <*>
    log_line2 = (
        "2026-10-30T10:15:31Z user sec_admin@corp.internal from 192.168.1.100 port 8080 "
        "session 123e4567-e89b-12d3-a456-426614174000 code 0xDEADBEEF processed 99 items"
    )
    result2 = miner.parse(log_line2, tenant_id=tid)
    assert result2.success is True
    attrs2 = result2.attributes
    assert attrs2 is not None

    # Numeric token '99' should be extracted as dynamic parameter <*> without becoming a PORT
    assert "99" in attrs2["parameters"]
    assert attrs2["masked_parameters"].get("PORT") == "8080"
    assert attrs2["masked_parameters"].get("PORT") != "99"

    # Test SourceInfo mapping
    assert result.source is not None
    assert result.source.ip == "192.168.1.100"
    assert result.source.port == 8080


def test_port_mask_variants() -> None:
    """Test all fixed-width lookbehind variants for port masking: port , PORT=, Port:, spt=, dpt=."""
    miner = DrainTemplateMiner(redis_enabled=False)

    variants = [
        ("Firewall accept connection port 22", "22"),
        ("Service listening on PORT=8443 ready", "8443"),
        ("Target service Port:9092 connected", "9092"),
        ("Inbound packet iptables spt=54321 logged", "54321"),
        ("Outbound packet iptables dpt=443 routed", "443"),
    ]

    for log, expected_port in variants:
        res = miner.parse(log, tenant_id=str(uuid4()))
        assert res.success is True
        assert res.attributes["masked_parameters"].get("PORT") == expected_port


# -------------------------------------------------------------------------
# 3. IPv6 Masking (full, compressed, and negative cases)
# -------------------------------------------------------------------------
def test_ipv6_masking_instruction_positive_cases() -> None:
    """Test positive IPv6 addresses (full, compressed loopback, link-local, and zero-compressed)."""
    masker = ValidatedIPv6MaskingInstruction("IPV6")

    positive_samples = [
        ("Host ::1 connected", "Host <IPV6> connected"),
        ("Listening on fe80::1 interface", "Listening on <IPV6> interface"),
        ("Source 2001:0db8:85a3:0000:0000:8a2e:0370:7334 seen", "Source <IPV6> seen"),
        ("Routed to 2001:db8::1 gateway", "Routed to <IPV6> gateway"),
    ]

    for text, expected in positive_samples:
        masked = masker.mask(text, "<", ">")
        assert masked == expected, f"Failed masking positive IPv6 text: {text}"


def test_ipv6_masking_instruction_negative_cases() -> None:
    """Test negative cases (timestamps, MAC addresses, colon strings) are never masked as IPV6."""
    masker = ValidatedIPv6MaskingInstruction("IPV6")

    negative_samples = [
        "Event logged at 12:34:56 today",
        "Interface MAC address 00:1A:2B:3C:4D:5E",
        "Key value pair prefix:action:status:detail",
    ]

    for text in negative_samples:
        masked = masker.mask(text, "<", ">")
        assert masked == text, f"Negative case incorrectly masked: {text} -> {masked}"


# -------------------------------------------------------------------------
# 4. Severity inference across keywords
# -------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("log_text", "expected_severity"),
    [
        ("oom-killer invoked: gfp_mask=0x1100cca", SeverityEnum.CRITICAL),
        ("FATAL: kernel panic - unable to mount root fs", SeverityEnum.CRITICAL),
        ("Critical power supply failure on rack 4", SeverityEnum.CRITICAL),
        ("Emergency system shutdown initiated", SeverityEnum.CRITICAL),
        ("java.lang.NullPointerException: Object is null", SeverityEnum.ERROR),
        ("org.springframework.Connect timed out after 5000ms", SeverityEnum.ERROR),
        ("ConnectionResetError: [Errno 104] Connection reset by peer", SeverityEnum.ERROR),
        ("Failed to authenticate user admin", SeverityEnum.ERROR),
        ("WARN: Disk usage above 85% on /dev/sda1", SeverityEnum.WARNING),
        ("Warning: certificate expires in 7 days", SeverityEnum.WARNING),
        ("Notice: user session refreshed", SeverityEnum.NOTICE),
        ("DEBUG: trace payload bytes: 0x48656c6c6f", SeverityEnum.DEBUG),
        ("Service started successfully listening on port 80", SeverityEnum.INFORMATIONAL),
    ],
)
def test_severity_inference(log_text: str, expected_severity: SeverityEnum) -> None:
    """Verify keyword and exception pattern severity inference heuristics."""
    assert infer_severity(log_text) == expected_severity


# -------------------------------------------------------------------------
# 5. Confidence precedence (generalized template gets 0.75, not 0.90)
# -------------------------------------------------------------------------
def test_confidence_precedence_generalized_template() -> None:
    """Verify confidence precedence:

    - cluster_created -> 0.50
    - cluster_template_changed (generalized, cluster_size >= 2) -> 0.75 (NOT 0.90)
    - change_type == 'none' (cluster_size >= 2) -> 0.90
    """
    miner = DrainTemplateMiner(redis_enabled=False)
    tid = str(uuid4())

    # 1. First log creates the cluster
    res1 = miner.parse("Connection failed for node-alpha at checkpoint", tenant_id=tid)
    assert res1.attributes["change_type"] == "cluster_created"
    assert res1.confidence == 0.50

    # 2. Second log generalises the cluster template ("node-alpha" vs "node-beta")
    # Even though cluster_size is now 2, change_type is 'cluster_template_changed' -> confidence 0.75!
    res2 = miner.parse("Connection failed for node-beta at checkpoint", tenant_id=tid)
    assert res2.attributes["change_type"] == "cluster_template_changed"
    assert res2.attributes["cluster_size"] == 2
    assert res2.confidence == 0.75, "Generalized template MUST receive 0.75, not 0.90"

    # 3. Third log matches the already-generalized template ("Connection failed for <*> at checkpoint")
    # change_type is 'none' and cluster_size >= 2 -> confidence 0.90!
    res3 = miner.parse("Connection failed for node-gamma at checkpoint", tenant_id=tid)
    assert res3.attributes["change_type"] == "none"
    assert res3.attributes["cluster_size"] == 3
    assert res3.confidence == 0.90


# -------------------------------------------------------------------------
# 6. Malformed and empty input handling
# -------------------------------------------------------------------------
def test_malformed_and_empty_input() -> None:
    """Empty or whitespace raw logs must return confidence=0.10, success=False, and not route to LLM."""
    miner = DrainTemplateMiner(redis_enabled=False)

    for empty_val in ["", "   ", "\t\n\r", "   \n"]:
        res = miner.parse(empty_val)
        assert res.success is False
        assert res.confidence == 0.10
        assert res.error_message == "Empty raw log"
        assert should_route_to_llm(res) is False

    # A valid novel log with confidence=0.50 should route to LLM
    novel_res = miner.parse("A completely brand new event that requires tier 3 review", tenant_id=str(uuid4()))
    assert novel_res.success is True
    assert novel_res.confidence == 0.50
    assert should_route_to_llm(novel_res) is True


# -------------------------------------------------------------------------
# 7. Eviction correctness (LRU pool flushes before eviction)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_pool_eviction_flushes_before_evicting() -> None:
    """AsyncTenantMinerPool past max_active_tenants flushes LRU tenant state before eviction."""
    pool = AsyncTenantMinerPool(max_active_tenants=2, redis_enabled=False)

    ctx1 = await pool.get_or_create("tenant-1")
    await pool.get_or_create("tenant-2")

    # Mock flush_sync on ctx1 to detect flush during eviction
    ctx1.flush_sync = MagicMock()  # type: ignore[method-assign]

    # Creating tenant-3 exceeds max_active_tenants=2; tenant-1 must be evicted and flushed
    ctx3 = await pool.get_or_create("tenant-3")

    assert ctx1.flush_sync.called
    assert "tenant-1" not in pool._cache
    assert "tenant-2" in pool._cache
    assert "tenant-3" in pool._cache
    assert ctx3.tenant_id == "tenant-3"


def test_pool_sync_eviction_flushes_before_evicting() -> None:
    """Sync pool eviction flushes LRU tenant state synchronously."""
    pool = AsyncTenantMinerPool(max_active_tenants=2, redis_enabled=False)

    ctx1 = pool.get_or_create_sync("tenant-a")
    pool.get_or_create_sync("tenant-b")

    ctx1.flush_sync = MagicMock()  # type: ignore[method-assign]

    pool.get_or_create_sync("tenant-c")

    assert ctx1.flush_sync.called
    assert "tenant-a" not in pool._cache
    assert "tenant-b" in pool._cache
    assert "tenant-c" in pool._cache


# -------------------------------------------------------------------------
# 8. Cold start (is_loaded gate)
# -------------------------------------------------------------------------
def test_cold_start_is_loaded_gate() -> None:
    """TenantMinerContext tracks is_loaded and triggers load_sync on cold start."""
    pool = AsyncTenantMinerPool(max_active_tenants=5, redis_enabled=False)

    ctx = pool.get_or_create_sync("tenant-cold")
    assert ctx.is_loaded is True


@pytest.mark.asyncio
async def test_cold_start_is_loaded_gate_async() -> None:
    """Async cold start invokes load_sync off-thread and marks is_loaded."""
    pool = AsyncTenantMinerPool(max_active_tenants=5, redis_enabled=False)

    ctx = await pool.get_or_create("tenant-cold-async")
    assert ctx.is_loaded is True


# -------------------------------------------------------------------------
# 9. Multi-tenant isolation
# -------------------------------------------------------------------------
def test_multi_tenant_isolation() -> None:
    """Verify clusters and mined templates do not leak across distinct tenant IDs."""
    miner = DrainTemplateMiner(redis_enabled=False)
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"

    # Tenant A sees authentication events
    res_a1 = miner.parse("AuthService: user alice logged in from 10.0.0.1", tenant_id=tenant_a)
    res_a2 = miner.parse("AuthService: user bob logged in from 10.0.0.2", tenant_id=tenant_a)
    assert res_a1.success and res_a2.success

    # Tenant B sees billing events
    res_b1 = miner.parse("BillingService: invoice 9901 charged successfully", tenant_id=tenant_b)
    assert res_b1.success

    ctx_a = miner.pool.get_or_create_sync(tenant_a)
    ctx_b = miner.pool.get_or_create_sync(tenant_b)

    # Tenant A clusters must only contain Tenant A patterns
    templates_a = [c.get_template() for c in ctx_a.miner.drain.id_to_cluster.values()]
    templates_b = [c.get_template() for c in ctx_b.miner.drain.id_to_cluster.values()]

    assert any("AuthService" in t for t in templates_a)
    assert not any("BillingService" in t for t in templates_a)

    assert any("BillingService" in t for t in templates_b)
    assert not any("AuthService" in t for t in templates_b)


# -------------------------------------------------------------------------
# 10. Concurrency under concurrent coroutines on the same tenant
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_concurrent_async_parsing_same_tenant() -> None:
    """Verify thread and async safety under high concurrent coroutine load on single tenant."""
    miner = DrainTemplateMiner(redis_enabled=False)
    tid = str(uuid4())

    log_templates = [
        f"Worker task_{i} executed step in {i * 10} ms status ok"
        for i in range(50)
    ]

    tasks = [miner.parse_async(log, tenant_id=tid) for log in log_templates]
    results = await asyncio.gather(*tasks)

    assert len(results) == 50
    for res in results:
        assert res.success is True
        assert res.parsed_by == ParsingTierEnum.TEMPLATE

    ctx = await miner.pool.get_or_create(tid)
    assert len(ctx.miner.drain.id_to_cluster) >= 1
    # Total logs clustered must sum to 50
    total_processed = sum(c.size for c in ctx.miner.drain.id_to_cluster.values())
    assert total_processed == 50


# -------------------------------------------------------------------------
# 11. Persistence round-trip (save/load state)
# -------------------------------------------------------------------------
def test_persistence_round_trip(tmp_path: Path) -> None:
    """Verify that cluster trees persist to disk and restore cleanly in a new pool."""
    tid = "tenant-persist-test"

    # Pool 1: mine templates and persist
    pool1 = AsyncTenantMinerPool(max_active_tenants=5, persistence_dir=tmp_path, redis_enabled=False)
    ctx1 = pool1.get_or_create_sync(tid)

    res1 = ctx1.miner.add_log_message("Database query SELECT * FROM users took 12 ms")
    assert res1["change_type"] == "cluster_created"
    res2 = ctx1.miner.add_log_message("Database query SELECT * FROM users took 45 ms")
    assert res2["change_type"] == "cluster_template_changed"
    ctx1.flush_sync("round_trip_test")

    expected_file = tmp_path / f"drain3_{tid}.bin"
    assert expected_file.exists(), "Persistence binary file was not created"

    # Pool 2: load existing state from the same directory
    pool2 = AsyncTenantMinerPool(max_active_tenants=5, persistence_dir=tmp_path, redis_enabled=False)
    ctx2 = pool2.get_or_create_sync(tid)

    # Context 2 should have restored the cluster from disk
    assert len(ctx2.miner.drain.id_to_cluster) >= 1
    matched = ctx2.miner.match("Database query SELECT * FROM users took 99 ms")
    assert matched is not None
    assert matched.cluster_id == res1["cluster_id"]


# -------------------------------------------------------------------------
# 12. Dry-run path (inspect_tier2 / inspect)
# -------------------------------------------------------------------------
def test_inspect_tier2_dry_run_non_mutating() -> None:
    """Verify inspect_tier2 performs read-only matching without mutating clusters or calling save_state."""
    miner = DrainTemplateMiner(redis_enabled=False)
    tid = str(uuid4())

    # Pre-populate one template via parse
    seed_res = miner.parse("AppServer: initialized worker thread pool", tenant_id=tid)
    assert seed_res.success is True

    ctx = miner.pool.get_or_create_sync(tid)
    initial_clusters = len(ctx.miner.drain.id_to_cluster)
    assert initial_clusters == 1

    # Mock save_state to ensure it is never invoked
    ctx.miner.save_state = MagicMock()  # type: ignore[method-assign]

    # 1. Matching existing log via inspect
    inspect_res = miner.inspect("AppServer: initialized worker thread pool", tenant_id=tid)
    assert inspect_res.success is True
    assert inspect_res.attributes["cluster_id"] == seed_res.attributes["cluster_id"]
    assert len(ctx.miner.drain.id_to_cluster) == initial_clusters
    assert not ctx.miner.save_state.called

    # 2. Inspecting completely novel log: returns success=False without creating a cluster
    novel_inspect = miner.inspect("Completely unprecedented security alert event", tenant_id=tid)
    assert novel_inspect.success is False
    assert novel_inspect.confidence == 0.20
    assert len(ctx.miner.drain.id_to_cluster) == initial_clusters
    assert not ctx.miner.save_state.called


# -------------------------------------------------------------------------
# 13. Public module-level entry points
# -------------------------------------------------------------------------
def test_public_entry_points() -> None:
    """Test parse_tier2, inspect_tier2, and parse_tier2_async public module functions."""
    raw = "Public entry point test log event with code 0x1234"

    res_sync = parse_tier2(raw)
    assert res_sync.success is True
    assert res_sync.parsed_by == ParsingTierEnum.TEMPLATE

    res_inspect = inspect_tier2(raw)
    assert res_inspect.success is True

    loop = asyncio.new_event_loop()
    try:
        res_async = loop.run_until_complete(parse_tier2_async(raw))
        assert res_async.success is True
    finally:
        loop.close()
