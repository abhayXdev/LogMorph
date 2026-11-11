"""MITRE ATT&CK schema definitions and rule data contracts for LogMorph.

Provides typed models for MITRE ATT&CK tactics, techniques, detection rules,
tagger configuration, and telemetry snapshots.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MitreTacticEnum(StrEnum):
    """Standard MITRE ATT&CK Enterprise Matrix Tactics."""

    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


TACTIC_NAME_MAP: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


class MitreAttackTag(BaseModel):
    """Normalized MITRE ATT&CK correlation tag."""

    model_config = ConfigDict(frozen=True)

    tactic_id: str = Field(description="MITRE ATT&CK Tactic ID (e.g. TA0006).")
    tactic_name: str = Field(description="MITRE ATT&CK Tactic human-readable name.")
    technique_id: str = Field(description="MITRE ATT&CK Technique ID (e.g. T1110.001).")
    technique_name: str = Field(description="MITRE ATT&CK Technique human-readable name.")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="Match confidence score.")
    matched_rule: str = Field(description="Identifier of the detection rule that triggered the tag.")
    description: str | None = Field(default=None, description="Detailed explanation of the technique.")


class MitreRule(BaseModel):
    """Detection rule mapping log signals to MITRE ATT&CK techniques."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(description="Unique rule identifier.")
    tactic_id: str = Field(description="Target MITRE tactic ID.")
    tactic_name: str = Field(description="Target MITRE tactic name.")
    technique_id: str = Field(description="Target MITRE technique ID.")
    technique_name: str = Field(description="Target MITRE technique name.")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="Detection confidence score.")
    action_patterns: list[str] = Field(
        default_factory=list,
        description="Regex or substring patterns matching normalized action strings.",
    )
    process_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns matching process names.",
    )
    raw_log_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns matching raw log text.",
    )
    threat_category_triggers: list[str] = Field(
        default_factory=list,
        description="Threat intel categories that trigger this rule.",
    )
    port_triggers: list[int] = Field(
        default_factory=list,
        description="Destination ports that trigger this rule.",
    )
    event_id_triggers: list[str] = Field(
        default_factory=list,
        description="Windows/Syslog Event IDs triggering this rule.",
    )
    description: str | None = Field(default=None, description="Rule description or rationale.")


class MitreTaggerConfig(BaseModel):
    """Configuration options for the MITRE ATT&CK Tagger."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = Field(default=True, description="Enable or disable MITRE tagging.")
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score required for tagging.",
    )
    cache_size: int = Field(
        default=10000,
        ge=100,
        description="Maximum capacity of LRU cache for MITRE tags.",
    )


class MitreMetricsSnapshot(BaseModel):
    """Thread-safe point-in-time metrics snapshot for MITRE tagging."""

    model_config = ConfigDict(frozen=True)

    total_events_tagged: int = Field(ge=0, description="Total events evaluated by tagger.")
    matches_detected: int = Field(ge=0, description="Total events successfully tagged.")
    untagged_events: int = Field(ge=0, description="Total events with no MITRE matches.")
    cache_hits: int = Field(ge=0, description="Total evaluations resolved from cache.")
    cache_misses: int = Field(ge=0, description="Total evaluations requiring rule execution.")
    tag_rate_pct: float = Field(ge=0.0, le=100.0, description="Percentage of events tagged.")
    tactic_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Count of detections grouped by MITRE Tactic ID.",
    )
