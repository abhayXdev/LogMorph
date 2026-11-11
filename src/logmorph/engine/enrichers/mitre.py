"""High-performance MITRE ATT&CK tagging and adversary behavioral correlation engine.

Maps normalized log actions, process telemetry, raw log patterns, network ports,
and threat intelligence indicators to the MITRE ATT&CK Enterprise Matrix (Tactics & Techniques).
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path

from cachetools import LRUCache  # type: ignore[import-untyped]

from logmorph.config import settings
from logmorph.domain.uls import (
    EnrichmentContext,
    SecurityContext,
    UniversalLogEvent,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.mitre import (
    TACTIC_NAME_MAP,
    MitreAttackTag,
    MitreMetricsSnapshot,
    MitreRule,
    MitreTacticEnum,
    MitreTaggerConfig,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# 1. Compiled Rule Model
# ==============================================================================


class _CompiledRule:
    """Internal optimized representation of a MitreRule with precompiled regexes."""

    def __init__(self, rule: MitreRule) -> None:
        self.rule = rule
        self.action_regexes = [re.compile(p) for p in rule.action_patterns]
        self.process_regexes = [re.compile(p) for p in rule.process_patterns]
        self.raw_log_regexes = [re.compile(p) for p in rule.raw_log_patterns]
        self.threat_categories = {c.strip().upper() for c in rule.threat_category_triggers}
        self.ports = set(rule.port_triggers)
        self.event_ids = {str(eid).strip() for eid in rule.event_id_triggers}

    def evaluate(
        self,
        action: str | None,
        process_name: str | None,
        raw_log: str | None,
        threat_categories: set[str],
        port: int | None,
        event_id: str | None,
    ) -> bool:
        """Evaluate signals against rule criteria; returns True on positive match."""
        # 1. Threat Intel category trigger
        if self.threat_categories and (threat_categories & self.threat_categories):
            return True

        # 2. Windows / Syslog Event ID trigger
        if event_id and self.event_ids and event_id in self.event_ids:
            return True

        # 3. Port trigger
        if port is not None and self.ports and port in self.ports:
            return True

        # 4. Process name regex match
        if (
            process_name
            and self.process_regexes
            and any(rx.search(process_name) for rx in self.process_regexes)
        ):
            return True

        # 5. Action regex match
        if (
            action
            and self.action_regexes
            and any(rx.search(action) for rx in self.action_regexes)
        ):
            return True

        # 6. Raw log regex match
        return bool(
            raw_log
            and self.raw_log_regexes
            and any(rx.search(raw_log) for rx in self.raw_log_regexes)
        )

    def to_tag(self) -> MitreAttackTag:
        """Instantiate a MitreAttackTag from this rule."""
        return MitreAttackTag(
            tactic_id=self.rule.tactic_id,
            tactic_name=self.rule.tactic_name,
            technique_id=self.rule.technique_id,
            technique_name=self.rule.technique_name,
            confidence=self.rule.confidence,
            matched_rule=self.rule.rule_id,
            description=self.rule.description,
        )


# ==============================================================================
# 2. Curated Embedded Enterprise Ruleset
# ==============================================================================


def get_default_curated_rules() -> list[MitreRule]:
    """Return comprehensive curated MITRE ATT&CK enterprise detection rules."""
    return [
        # --- Credential Access (TA0006) ---
        MitreRule(
            rule_id="RULE_CRED_PASSWORD_GUESSING",
            tactic_id=MitreTacticEnum.CREDENTIAL_ACCESS,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.CREDENTIAL_ACCESS],
            technique_id="T1110.001",
            technique_name="Password Guessing",
            confidence=0.96,
            action_patterns=[r"(?i)^login_failed$", r"(?i)^authentication_failed$", r"(?i)^failed_password$"],
            event_id_triggers=["4625"],
            raw_log_patterns=[
                r"(?i)failed\s+password\s+for",
                r"(?i)authentication\s+failure",
                r"(?i)invalid\s+user",
                r"(?i)logon\s+failure",
            ],
            description="Failed authentication or brute-force password guessing attempt.",
        ),
        MitreRule(
            rule_id="RULE_CRED_PASSWORD_SPRAY",
            tactic_id=MitreTacticEnum.CREDENTIAL_ACCESS,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.CREDENTIAL_ACCESS],
            technique_id="T1110.003",
            technique_name="Password Spraying",
            confidence=0.94,
            action_patterns=[r"(?i)^password_spray$"],
            raw_log_patterns=[r"(?i)password\s+spray(?:ing)?"],
            description="Password spray attack testing a single password against multiple accounts.",
        ),
        MitreRule(
            rule_id="RULE_CRED_LSASS_DUMP",
            tactic_id=MitreTacticEnum.CREDENTIAL_ACCESS,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.CREDENTIAL_ACCESS],
            technique_id="T1003.001",
            technique_name="LSASS Memory Dumping",
            confidence=0.99,
            process_patterns=[r"(?i)mimikatz(?:\.exe)?$", r"(?i)procdump(?:\.exe)?$"],
            raw_log_patterns=[
                r"(?i)sekurlsa::logonpasswords",
                r"(?i)lsass(?:\.exe)?\s+memory",
                r"(?i)mimikatz",
            ],
            description="Dumping plaintext credentials or hashes from LSASS process memory.",
        ),
        # --- Execution (TA0002) ---
        MitreRule(
            rule_id="RULE_EXEC_POWERSHELL",
            tactic_id=MitreTacticEnum.EXECUTION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.EXECUTION],
            technique_id="T1059.001",
            technique_name="PowerShell",
            confidence=0.95,
            process_patterns=[r"(?i)powershell(?:\.exe)?$", r"(?i)pwsh(?:\.exe)?$"],
            raw_log_patterns=[
                r"(?i)powershell.*-(?:enc|encodedcommand|executionpolicy\s+bypass|windowstyle\s+hidden)",
                r"(?i)downloadstring",
                r"(?i)invoke-expression|iex\b",
            ],
            description="Adversary execution of obfuscated or interactive PowerShell commands.",
        ),
        MitreRule(
            rule_id="RULE_EXEC_UNIX_SHELL",
            tactic_id=MitreTacticEnum.EXECUTION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.EXECUTION],
            technique_id="T1059.004",
            technique_name="Unix Shell",
            confidence=0.92,
            process_patterns=[r"^/(?:usr/)?bin/(?:ba)?sh$", r"^/(?:usr/)?bin/zsh$"],
            raw_log_patterns=[
                r"(?i)bash\s+-i\s+>&",
                r"/dev/tcp/\d+",
                r"(?i)nc\s+-e\s+/bin/(?:ba)?sh",
            ],
            description="Interactive Unix shell execution or reverse TCP shell invocation.",
        ),
        MitreRule(
            rule_id="RULE_EXEC_WMI",
            tactic_id=MitreTacticEnum.EXECUTION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.EXECUTION],
            technique_id="T1047",
            technique_name="Windows Management Instrumentation",
            confidence=0.91,
            process_patterns=[r"(?i)wmic(?:\.exe)?$"],
            raw_log_patterns=[r"(?i)wmic\s+process\s+call\s+create"],
            description="Execution of malicious commands via Windows Management Instrumentation (WMI).",
        ),
        # --- Privilege Escalation (TA0004) ---
        MitreRule(
            rule_id="RULE_PRIV_SUDO_ELEVATION",
            tactic_id=MitreTacticEnum.PRIVILEGE_ESCALATION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.PRIVILEGE_ESCALATION],
            technique_id="T1548.003",
            technique_name="Sudo and Sudo Caching",
            confidence=0.93,
            action_patterns=[r"(?i)^sudo_exec$", r"(?i)^privilege_escalation$"],
            raw_log_patterns=[r"(?i)sudo:\s+.*COMMAND=", r"(?i)sudo\s+su\s+-?"],
            description="Execution of elevated administrative commands using sudo.",
        ),
        MitreRule(
            rule_id="RULE_PRIV_UAC_BYPASS",
            tactic_id=MitreTacticEnum.PRIVILEGE_ESCALATION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.PRIVILEGE_ESCALATION],
            technique_id="T1548.002",
            technique_name="Bypass User Account Control",
            confidence=0.90,
            process_patterns=[
                r"(?i)fodhelper(?:\.exe)?$",
                r"(?i)eventvwr(?:\.exe)?$",
                r"(?i)sdclt(?:\.exe)?$",
                r"(?i)slui(?:\.exe)?$",
            ],
            raw_log_patterns=[r"(?i)uac\s+bypass"],
            description="Bypassing Windows User Account Control (UAC) to obtain elevated integrity.",
        ),
        MitreRule(
            rule_id="RULE_PRIV_SPECIAL_PRIVILEGES",
            tactic_id=MitreTacticEnum.PRIVILEGE_ESCALATION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.PRIVILEGE_ESCALATION],
            technique_id="T1078",
            technique_name="Valid Accounts",
            confidence=0.88,
            event_id_triggers=["4672"],
            raw_log_patterns=[r"(?i)special\s+privileges\s+assigned\s+to\s+new\s+logon"],
            description="Special administrative privileges assigned during account logon.",
        ),
        # --- Defense Evasion (TA0005) ---
        MitreRule(
            rule_id="RULE_EVASION_CLEAR_LOGS",
            tactic_id=MitreTacticEnum.DEFENSE_EVASION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.DEFENSE_EVASION],
            technique_id="T1070.001",
            technique_name="Clear Windows Event Logs",
            confidence=0.98,
            event_id_triggers=["1102", "104"],
            process_patterns=[r"(?i)wevtutil(?:\.exe)?$"],
            raw_log_patterns=[
                r"(?i)wevtutil\s+cl",
                r"(?i)audit\s+log\s+was\s+cleared",
                r"(?i)event\s+log\s+was\s+cleared",
            ],
            description="Destruction or clearing of security audit logs to eliminate forensic evidence.",
        ),
        # --- Discovery (TA0007) ---
        MitreRule(
            rule_id="RULE_DISC_NETWORK_SERVICE_SCAN",
            tactic_id=MitreTacticEnum.DISCOVERY,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.DISCOVERY],
            technique_id="T1046",
            technique_name="Network Service Discovery",
            confidence=0.94,
            action_patterns=[r"(?i)^port_scan$", r"(?i)^scan_detected$"],
            process_patterns=[r"(?i)nmap$", r"(?i)masscan$", r"(?i)zmap$"],
            threat_category_triggers=["SCANNER"],
            raw_log_patterns=[
                r"(?i)port\s+scan",
                r"(?i)syn\s+stealth\s+scan",
                r"(?i)nmap\s+scan",
            ],
            description="Host or network service discovery scanning to identify open attack surfaces.",
        ),
        # --- Lateral Movement (TA0008) ---
        MitreRule(
            rule_id="RULE_LAT_RDP",
            tactic_id=MitreTacticEnum.LATERAL_MOVEMENT,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.LATERAL_MOVEMENT],
            technique_id="T1021.001",
            technique_name="Remote Desktop Protocol",
            confidence=0.89,
            port_triggers=[3389],
            process_patterns=[r"(?i)mstsc(?:\.exe)?$"],
            raw_log_patterns=[r"(?i)rdp\s+connection", r"(?i)RemoteDesktop", r"(?i)TermDD"],
            description="Remote Desktop Protocol (RDP) connection or interactive session lateral movement.",
        ),
        MitreRule(
            rule_id="RULE_LAT_SMB_ADMIN_SHARES",
            tactic_id=MitreTacticEnum.LATERAL_MOVEMENT,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.LATERAL_MOVEMENT],
            technique_id="T1021.002",
            technique_name="SMB/Windows Admin Shares",
            confidence=0.92,
            port_triggers=[445, 139],
            process_patterns=[r"(?i)psexec(?:\.exe)?$"],
            raw_log_patterns=[r"(?i)ADMIN\$", r"(?i)IPC\$", r"(?i)C\$", r"(?i)psexec"],
            description="Lateral movement utilizing SMB administrative shares or PsExec.",
        ),
        # --- Command and Control (TA0011) ---
        MitreRule(
            rule_id="RULE_C2_WEB_PROTOCOLS",
            tactic_id=MitreTacticEnum.COMMAND_AND_CONTROL,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.COMMAND_AND_CONTROL],
            technique_id="T1071.001",
            technique_name="Web Protocols",
            confidence=0.98,
            threat_category_triggers=["C2_SERVER"],
            raw_log_patterns=[
                r"(?i)cobalt\s*strike",
                r"(?i)c2\s*beacon",
                r"(?i)beacon\s*check-in",
            ],
            description="Adversary Command and Control communications over standard web protocols (HTTP/HTTPS).",
        ),
        MitreRule(
            rule_id="RULE_C2_DNS_TUNNELING",
            tactic_id=MitreTacticEnum.COMMAND_AND_CONTROL,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.COMMAND_AND_CONTROL],
            technique_id="T1071.004",
            technique_name="DNS Tunneling",
            confidence=0.93,
            raw_log_patterns=[r"(?i)dns\s+tunnel", r"(?i)iodine", r"(?i)dnscat2"],
            description="Adversary C2 communication masked within standard DNS protocol requests.",
        ),
        MitreRule(
            rule_id="RULE_C2_TOR_PROXY",
            tactic_id=MitreTacticEnum.COMMAND_AND_CONTROL,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.COMMAND_AND_CONTROL],
            technique_id="T1090.003",
            technique_name="Multi-hop Proxy",
            confidence=0.95,
            threat_category_triggers=["TOR_EXIT_NODE"],
            raw_log_patterns=[r"(?i)tor\s+exit", r"(?i)onion\s+routing"],
            description="Traffic routed through the multi-hop anonymized Tor network.",
        ),
        # --- Impact (TA0040) ---
        MitreRule(
            rule_id="RULE_IMPACT_RANSOMWARE_ENCRYPTION",
            tactic_id=MitreTacticEnum.IMPACT,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.IMPACT],
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            confidence=0.98,
            action_patterns=[r"(?i)^file_encrypted$", r"(?i)^mass_file_modification$"],
            raw_log_patterns=[
                r"(?i)wannacry",
                r"(?i)ransomware",
                r"(?i)files?\s+encrypted",
                r"(?i)\.locked\b",
            ],
            description="Malicious encryption of files, shares, or systems rendering data unusable.",
        ),
        MitreRule(
            rule_id="RULE_IMPACT_INHIBIT_RECOVERY",
            tactic_id=MitreTacticEnum.IMPACT,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.IMPACT],
            technique_id="T1490",
            technique_name="Inhibit System Recovery",
            confidence=0.99,
            process_patterns=[r"(?i)vssadmin(?:\.exe)?$", r"(?i)bcdedit(?:\.exe)?$"],
            raw_log_patterns=[
                r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows",
                r"(?i)bcdedit.*recoveryenabled\s+no",
                r"(?i)wbadmin\s+delete\s+catalog",
            ],
            description="Deletion of volume shadow copies or disabling recovery to prevent system restoration.",
        ),
        # --- Initial Access (TA0001) ---
        MitreRule(
            rule_id="RULE_INIT_SPEARPHISHING_LINK",
            tactic_id=MitreTacticEnum.INITIAL_ACCESS,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.INITIAL_ACCESS],
            technique_id="T1566.002",
            technique_name="Spearphishing Link",
            confidence=0.95,
            threat_category_triggers=["PHISHING"],
            raw_log_patterns=[
                r"(?i)phish.*login",
                r"(?i)credential\s+harvesting",
                r"(?i)spearphish",
            ],
            description="Luring victims to click malicious links leading to credential harvesting.",
        ),
        MitreRule(
            rule_id="RULE_INIT_EXPLOIT_PUBLIC_APP",
            tactic_id=MitreTacticEnum.INITIAL_ACCESS,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.INITIAL_ACCESS],
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            confidence=0.94,
            action_patterns=[r"(?i)^web_exploit$", r"(?i)^cve_exploit$"],
            raw_log_patterns=[
                r"(?i)cve-\d{4}-\d+",
                r"(?i)log4j",
                r"(?i)jndi:ldap",
                r"(?i)path\s+traversal",
                r"(?i)sql\s+injection",
            ],
            description="Exploitation of software weaknesses in Internet-facing applications.",
        ),
        # --- Persistence (TA0003) ---
        MitreRule(
            rule_id="RULE_PERSIST_SERVICE_INSTALL",
            tactic_id=MitreTacticEnum.PERSISTENCE,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.PERSISTENCE],
            technique_id="T1543.003",
            technique_name="Windows Service",
            confidence=0.93,
            action_patterns=[r"(?i)^service_install$", r"(?i)^service_created$"],
            event_id_triggers=["7045"],
            raw_log_patterns=[r"(?i)a\s+service\s+was\s+installed", r"(?i)sc\s+create"],
            description="Installation of unauthorized Windows services to establish persistence.",
        ),
        # --- Exfiltration (TA0010) ---
        MitreRule(
            rule_id="RULE_EXFIL_ALTERNATIVE_PROTOCOL",
            tactic_id=MitreTacticEnum.EXFILTRATION,
            tactic_name=TACTIC_NAME_MAP[MitreTacticEnum.EXFILTRATION],
            technique_id="T1048",
            technique_name="Exfiltration Over Alternative Protocol",
            confidence=0.91,
            action_patterns=[r"(?i)^data_exfiltration$", r"(?i)^exfil_detected$"],
            raw_log_patterns=[
                r"(?i)data\s+exfiltration",
                r"(?i)unauthorized\s+data\s+transfer",
                r"(?i)large\s+outbound\s+transfer",
            ],
            description="Adversary exfiltration of sensitive organizational data over alternate channels.",
        ),
    ]


# ==============================================================================
# 3. Telemetry Collector
# ==============================================================================


class MitreMetrics:
    """Thread-safe telemetry collector for MITRE ATT&CK tagging operations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_events_tagged: int = 0
        self._matches_detected: int = 0
        self._untagged_events: int = 0
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._tactic_counts: dict[str, int] = {}

    def record_tag_evaluation(
        self,
        tags: list[MitreAttackTag],
        is_cache_hit: bool,
    ) -> None:
        """Record the outcome of a tag evaluation turn."""
        with self._lock:
            self._total_events_tagged += 1
            if tags:
                self._matches_detected += 1
                for tag in tags:
                    self._tactic_counts[tag.tactic_id] = (
                        self._tactic_counts.get(tag.tactic_id, 0) + 1
                    )
            else:
                self._untagged_events += 1

            if is_cache_hit:
                self._cache_hits += 1
            else:
                self._cache_misses += 1

    def get_snapshot(self) -> MitreMetricsSnapshot:
        """Generate an immutable point-in-time metrics snapshot."""
        with self._lock:
            rate = (
                (self._matches_detected / self._total_events_tagged * 100.0)
                if self._total_events_tagged > 0
                else 0.0
            )
            return MitreMetricsSnapshot(
                total_events_tagged=self._total_events_tagged,
                matches_detected=self._matches_detected,
                untagged_events=self._untagged_events,
                cache_hits=self._cache_hits,
                cache_misses=self._cache_misses,
                tag_rate_pct=round(rate, 2),
                tactic_counts=dict(self._tactic_counts),
            )

    def reset(self) -> None:
        """Reset all counters and tactic tallies to zero."""
        with self._lock:
            self._total_events_tagged = 0
            self._matches_detected = 0
            self._untagged_events = 0
            self._cache_hits = 0
            self._cache_misses = 0
            self._tactic_counts.clear()


# Global singleton metrics collector
mitre_metrics = MitreMetrics()


# ==============================================================================
# 4. MITRE ATT&CK Tagger Engine
# ==============================================================================


class MitreAttackTagger:
    """High-throughput, multi-signal MITRE ATT&CK adversary tagging engine.

    Evaluates log events across actions, process telemetry, raw log patterns,
    event IDs, ports, and threat intelligence findings, and enriches ULS models
    with standard TTP classifications.
    """

    def __init__(
        self,
        rules: list[MitreRule] | None = None,
        config: MitreTaggerConfig | None = None,
        metrics: MitreMetrics | None = None,
    ) -> None:
        self._config = config or MitreTaggerConfig(
            enabled=settings.MITRE_TAGGER_ENABLED,
        )
        self._metrics = metrics or mitre_metrics

        # Thread-safe LRU cache
        self._cache_lock = threading.Lock()
        self._cache: LRUCache[str, list[MitreAttackTag]] = LRUCache(
            maxsize=self._config.cache_size,
        )

        # Rule storage
        self._rule_lock = threading.Lock()
        self._rules: list[_CompiledRule] = []

        base_rules = rules if rules is not None else get_default_curated_rules()
        for r in base_rules:
            self.add_rule(r)

        # Load external rules file if configured
        if settings.MITRE_RULES_PATH:
            self.load_rules_from_file(settings.MITRE_RULES_PATH)

    @property
    def config(self) -> MitreTaggerConfig:
        return self._config

    @property
    def metrics(self) -> MitreMetrics:
        return self._metrics

    def add_rule(self, rule: MitreRule) -> None:
        """Register a new detection rule in the compiled rule table."""
        compiled = _CompiledRule(rule)
        with self._rule_lock:
            self._rules.append(compiled)

    def load_rules_from_file(self, rules_path: str) -> None:
        """Load external detection rules from a JSON file."""
        path = Path(rules_path)
        if not path.is_file():
            logger.warning("MITRE rules file not found: %s", rules_path)
            return

        try:
            with path.open("r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return
                records = json.loads(content)
                if isinstance(records, list):
                    for rec in records:
                        self.add_rule(MitreRule(**rec))
                logger.info("Loaded %d MITRE rules from %s", len(records), rules_path)
        except Exception as exc:
            logger.error("Failed to load MITRE rules file %s: %s", rules_path, exc)

    def _extract_signals(
        self,
        event: UniversalLogEvent,
    ) -> tuple[
        str | None,
        str | None,
        str | None,
        set[str],
        int | None,
        str | None,
    ]:
        """Extract multi-signal correlation parameters from UniversalLogEvent."""
        action = event.action
        process_name = event.security.process_name if event.security else None
        raw_log = event.raw_log

        threat_cats: set[str] = set()
        if "threat_intel" in event.attributes and isinstance(
            event.attributes["threat_intel"], dict
        ):
            cat = event.attributes["threat_intel"].get("category")
            if cat:
                threat_cats.add(str(cat).strip().upper())

        # Also inspect security threat_id if present
        if event.security and event.security.threat_id:
            tid_upper = event.security.threat_id.upper()
            if "C2" in tid_upper or "COBALT" in tid_upper:
                threat_cats.add("C2_SERVER")
            elif "TOR" in tid_upper:
                threat_cats.add("TOR_EXIT_NODE")
            elif "SCANNER" in tid_upper:
                threat_cats.add("SCANNER")
            elif "WANNACRY" in tid_upper or "MALWARE" in tid_upper:
                threat_cats.add("MALWARE")

        port = event.destination.port if event.destination else None

        # Check for event IDs in attributes
        event_id = None
        for key in ["EventID", "event_id", "eventId", "id"]:
            val = event.attributes.get(key)
            if val is not None:
                event_id = str(val).strip()
                break

        return action, process_name, raw_log, threat_cats, port, event_id

    def _generate_cache_key(
        self,
        action: str | None,
        process_name: str | None,
        threat_cats: set[str],
        port: int | None,
        event_id: str | None,
        raw_log: str | None,
    ) -> str:
        """Construct a lightweight deterministic cache key."""
        cats_str = ",".join(sorted(threat_cats))
        raw_sig = raw_log[:100] if raw_log else ""
        return f"{action or ''}|{process_name or ''}|{cats_str}|{port or ''}|{event_id or ''}|{raw_sig}"

    def tag_event(self, event: UniversalLogEvent) -> list[MitreAttackTag]:
        """Evaluate candidate adversary signals in event against rule table."""
        if not self._config.enabled:
            return []

        action, process, raw, threat_cats, port, eid = self._extract_signals(event)
        cache_key = self._generate_cache_key(
            action, process, threat_cats, port, eid, raw
        )

        with self._cache_lock:
            if cache_key in self._cache:
                cached_tags: list[MitreAttackTag] = list(self._cache[cache_key])
                self._metrics.record_tag_evaluation(
                    tags=cached_tags,
                    is_cache_hit=True,
                )
                return cached_tags

        # Execute Rule Table
        matched_tags: list[MitreAttackTag] = []
        with self._rule_lock:
            for rule_entry in self._rules:
                if rule_entry.rule.confidence < self._config.confidence_threshold:
                    continue
                if rule_entry.evaluate(action, process, raw, threat_cats, port, eid):
                    matched_tags.append(rule_entry.to_tag())

        # Store in LRU cache
        with self._cache_lock:
            self._cache[cache_key] = matched_tags

        self._metrics.record_tag_evaluation(
            tags=matched_tags,
            is_cache_hit=False,
        )
        return matched_tags

    def enrich_event(self, event: UniversalLogEvent) -> UniversalLogEvent:
        """Enrich UniversalLogEvent with primary and full MITRE ATT&CK metadata."""
        if not self._config.enabled:
            return event

        matches = self.tag_event(event)
        if not matches:
            return event

        # Pick highest-confidence match
        best_match = max(matches, key=lambda m: (m.confidence, m.tactic_id))

        updated_enrichment = (
            event.enrichment.model_copy()
            if event.enrichment
            else EnrichmentContext()
        )
        updated_enrichment.mitre_technique = best_match.technique_id
        updated_enrichment.mitre_tactic = best_match.tactic_id

        updated_security = (
            event.security.model_copy()
            if event.security
            else SecurityContext()
        )
        updated_security.mitre_technique = best_match.technique_id

        updated_attrs = dict(event.attributes)
        updated_attrs["mitre_attack"] = best_match.model_dump()
        if len(matches) > 1:
            updated_attrs["mitre_attack_all"] = [m.model_dump() for m in matches]

        return event.model_copy(
            update={
                "enrichment": updated_enrichment,
                "security": updated_security,
                "attributes": updated_attrs,
            }
        )

    def enrich_parsed_result(self, result: ParsedResult) -> ParsedResult:
        """Evaluate signals within a ParsedResult and inject MITRE telemetry."""
        if not self._config.enabled:
            return result

        action = result.action
        process_name = result.security.process_name if result.security else None
        raw_msg: str | None = None
        for key in ["message", "raw_message", "msg"]:
            v = result.attributes.get(key)
            if v and isinstance(v, str):
                raw_msg = v
                break

        threat_cats: set[str] = set()
        if "threat_intel" in result.attributes and isinstance(
            result.attributes["threat_intel"], dict
        ):
            cat = result.attributes["threat_intel"].get("category")
            if cat:
                threat_cats.add(str(cat).strip().upper())

        port = result.destination.port if result.destination else None
        event_id: str | None = None
        for key in ["EventID", "event_id", "eventId"]:
            ev = result.attributes.get(key)
            if ev is not None:
                event_id = str(ev).strip()
                break

        cache_key = self._generate_cache_key(
            action, process_name, threat_cats, port, event_id, raw_msg
        )

        with self._cache_lock:
            if cache_key in self._cache:
                matches: list[MitreAttackTag] = list(self._cache[cache_key])
                self._metrics.record_tag_evaluation(tags=matches, is_cache_hit=True)
            else:
                matches = []
                with self._rule_lock:
                    for rule_entry in self._rules:
                        if rule_entry.rule.confidence < self._config.confidence_threshold:
                            continue
                        if rule_entry.evaluate(
                            action, process_name, raw_msg, threat_cats, port, event_id
                        ):
                            matches.append(rule_entry.to_tag())
                self._cache[cache_key] = matches
                self._metrics.record_tag_evaluation(tags=matches, is_cache_hit=False)

        if not matches:
            return result

        best_match = max(matches, key=lambda m: (m.confidence, m.tactic_id))

        updated_attrs = dict(result.attributes)
        updated_attrs["mitre_technique"] = best_match.technique_id
        updated_attrs["mitre_tactic"] = best_match.tactic_id
        updated_attrs["mitre_attack"] = best_match.model_dump()
        if len(matches) > 1:
            updated_attrs["mitre_attack_all"] = [m.model_dump() for m in matches]

        updated_security = (
            result.security.model_copy()
            if result.security
            else SecurityContext()
        )
        updated_security.mitre_technique = best_match.technique_id

        return result.model_copy(
            update={
                "attributes": updated_attrs,
                "security": updated_security,
            }
        )

    def clear_cache(self) -> None:
        """Clear the in-memory LRU cache."""
        with self._cache_lock:
            self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Return the current number of cached signatures."""
        with self._cache_lock:
            return len(self._cache)

    @property
    def rule_count(self) -> int:
        """Return the count of registered detection rules."""
        with self._rule_lock:
            return len(self._rules)


# ==============================================================================
# 5. Global Factory / Singleton Accessor
# ==============================================================================

_global_mitre_tagger: MitreAttackTagger | None = None
_global_tagger_lock = threading.Lock()


def get_mitre_tagger() -> MitreAttackTagger:
    """Return the global shared singleton MitreAttackTagger instance."""
    global _global_mitre_tagger
    if _global_mitre_tagger is None:
        with _global_tagger_lock:
            if _global_mitre_tagger is None:
                _global_mitre_tagger = MitreAttackTagger()
    return _global_mitre_tagger
