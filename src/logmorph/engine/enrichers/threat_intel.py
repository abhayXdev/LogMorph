"""Threat Intelligence correlation and IOC matching engine.

Provides multi-IOC extraction (IPs, domains, hashes, CIDRs), mockable provider architecture,
curated embedded threat feeds, in-memory LRU caching, and ULS security enrichment.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
from abc import ABC, abstractmethod
from pathlib import Path

from cachetools import LRUCache  # type: ignore[import-untyped]

from logmorph.config import settings
from logmorph.domain.uls import (
    EnrichmentContext,
    SecurityContext,
    SeverityEnum,
    UniversalLogEvent,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.threat_intel import (
    IOCTypeEnum,
    ThreatCategoryEnum,
    ThreatIndicator,
    ThreatIntelConfig,
    ThreatIntelMetricsSnapshot,
    ThreatIntelResult,
)

logger = logging.getLogger(__name__)

# Pre-compiled hash validation patterns
_RE_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
_RE_MD5 = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)


# ==============================================================================
# 1. Provider Interfaces and Implementations
# ==============================================================================


class BaseThreatIntelProvider(ABC):
    """Abstract provider interface for threat intelligence feeds."""

    @abstractmethod
    def lookup_ioc(
        self,
        value: str,
        ioc_type: IOCTypeEnum | None = None,
    ) -> ThreatIndicator | None:
        """Query provider for an IOC indicator."""
        pass

    @abstractmethod
    def get_indicators(self) -> list[ThreatIndicator]:
        """Return all indicators loaded in this provider."""
        pass


class LocalThreatIntelProvider(BaseThreatIntelProvider):
    """Local threat intelligence provider with embedded indicators and JSON file loading."""

    def __init__(self, feed_path: str | None = None) -> None:
        self._exact_indicators: dict[tuple[IOCTypeEnum, str], ThreatIndicator] = {}
        self._cidr_indicators: list[
            tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ThreatIndicator]
        ] = []
        self._load_curated_embedded_feed()
        if feed_path:
            self.load_feed_from_file(feed_path)

    def _load_curated_embedded_feed(self) -> None:
        """Load built-in, verified threat indicators."""
        curated_list: list[ThreatIndicator] = [
            # --- C2 Server IPs ---
            ThreatIndicator(
                ioc_value="194.26.29.112",
                ioc_type=IOCTypeEnum.IP,
                threat_name="Cobalt Strike C2",
                category=ThreatCategoryEnum.C2_SERVER,
                severity=SeverityEnum.CRITICAL,
                confidence=0.98,
                source_feed="EMBEDDED_LOCAL",
                description="Active Cobalt Strike malleable C2 beacon listener.",
            ),
            ThreatIndicator(
                ioc_value="185.220.101.5",
                ioc_type=IOCTypeEnum.IP,
                threat_name="Tor Exit Relay",
                category=ThreatCategoryEnum.TOR_EXIT_NODE,
                severity=SeverityEnum.WARNING,
                confidence=0.95,
                source_feed="EMBEDDED_LOCAL",
                description="Known public Tor exit node participating in anonymous traffic.",
            ),
            ThreatIndicator(
                ioc_value="198.51.100.200",
                ioc_type=IOCTypeEnum.IP,
                threat_name="Emotet C2 Server",
                category=ThreatCategoryEnum.C2_SERVER,
                severity=SeverityEnum.CRITICAL,
                confidence=0.99,
                source_feed="EMBEDDED_LOCAL",
                description="Verified Emotet epoch banking trojan command server.",
            ),
            ThreatIndicator(
                ioc_value="45.33.32.156",
                ioc_type=IOCTypeEnum.IP,
                threat_name="Mirai Botnet Scanner",
                category=ThreatCategoryEnum.BOTNET,
                severity=SeverityEnum.ERROR,
                confidence=0.92,
                source_feed="EMBEDDED_LOCAL",
                description="Host engaged in aggressive Telnet/SSH credential brute-forcing.",
            ),
            # --- Malicious CIDR Subnets ---
            ThreatIndicator(
                ioc_value="198.51.100.192/28",
                ioc_type=IOCTypeEnum.CIDR,
                threat_name="Malicious Scanner Subnet",
                category=ThreatCategoryEnum.SCANNER,
                severity=SeverityEnum.ERROR,
                confidence=0.90,
                source_feed="EMBEDDED_LOCAL",
                description="Rented bulletproof hosting subnet used exclusively for offensive port scans.",
            ),
            # --- Malicious Domains & FQDNs ---
            ThreatIndicator(
                ioc_value="evil-c2-beacon.top",
                ioc_type=IOCTypeEnum.DOMAIN,
                threat_name="Cobalt Strike Domain",
                category=ThreatCategoryEnum.C2_SERVER,
                severity=SeverityEnum.CRITICAL,
                confidence=0.96,
                source_feed="EMBEDDED_LOCAL",
                description="Domain used for DNS tunneling and beacon check-ins.",
            ),
            ThreatIndicator(
                ioc_value="phish-secure-login.xyz",
                ioc_type=IOCTypeEnum.DOMAIN,
                threat_name="Banking Phishing Kit",
                category=ThreatCategoryEnum.PHISHING,
                severity=SeverityEnum.ERROR,
                confidence=0.94,
                source_feed="EMBEDDED_LOCAL",
                description="Credential harvesting portal masquerading as single sign-on page.",
            ),
            ThreatIndicator(
                ioc_value="malware-drop-payload.com",
                ioc_type=IOCTypeEnum.DOMAIN,
                threat_name="Malware Distribution Site",
                category=ThreatCategoryEnum.MALWARE,
                severity=SeverityEnum.CRITICAL,
                confidence=0.97,
                source_feed="EMBEDDED_LOCAL",
                description="Web server hosting stage-2 second-stage obfuscated payload drops.",
            ),
            # --- Malware File Hashes ---
            ThreatIndicator(
                ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                ioc_type=IOCTypeEnum.SHA256,
                threat_name="EICAR Standard AV Test File",
                category=ThreatCategoryEnum.MALWARE,
                severity=SeverityEnum.NOTICE,
                confidence=1.0,
                source_feed="EMBEDDED_LOCAL",
                description="Standard test string for anti-virus and security telemetry verification.",
            ),
            ThreatIndicator(
                ioc_value="24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
                ioc_type=IOCTypeEnum.SHA256,
                threat_name="WannaCry Ransomware",
                category=ThreatCategoryEnum.MALWARE,
                severity=SeverityEnum.CRITICAL,
                confidence=1.0,
                source_feed="EMBEDDED_LOCAL",
                description="WannaCry cryptoworm payload binary SHA-256.",
            ),
            ThreatIndicator(
                ioc_value="84c82835a5d21bbcf75a61706d8ab549",
                ioc_type=IOCTypeEnum.MD5,
                threat_name="WannaCry Ransomware (MD5)",
                category=ThreatCategoryEnum.MALWARE,
                severity=SeverityEnum.CRITICAL,
                confidence=1.0,
                source_feed="EMBEDDED_LOCAL",
                description="WannaCry ransomware binary MD5 digest.",
            ),
            ThreatIndicator(
                ioc_value="4f9972dd4703a4b9c1d6833923a105eb9941a4a159938d21b798cf01b63ddab6",
                ioc_type=IOCTypeEnum.SHA256,
                threat_name="Emotet Dropper Binary",
                category=ThreatCategoryEnum.MALWARE,
                severity=SeverityEnum.CRITICAL,
                confidence=0.99,
                source_feed="EMBEDDED_LOCAL",
                description="Emotet modular banking trojan execution dropper.",
            ),
        ]

        for ind in curated_list:
            self.add_indicator(ind)

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Register an indicator in the local provider."""
        normalized_val = indicator.ioc_value.strip().lower()

        if indicator.ioc_type == IOCTypeEnum.CIDR:
            try:
                net = ipaddress.ip_network(normalized_val, strict=False)
                self._cidr_indicators.append((net, indicator))
            except ValueError as exc:
                logger.warning("Invalid CIDR in threat feed %s: %s", normalized_val, exc)
        else:
            self._exact_indicators[(indicator.ioc_type, normalized_val)] = indicator

    def load_feed_from_file(self, feed_path: str) -> None:
        """Load indicators from a JSON or JSON Lines feed file."""
        path = Path(feed_path)
        if not path.is_file():
            logger.warning("Threat feed file not found: %s", feed_path)
            return

        try:
            with path.open("r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return
                # Try array format
                if content.startswith("["):
                    records = json.loads(content)
                    for rec in records:
                        self.add_indicator(ThreatIndicator(**rec))
                else:
                    # JSON Lines format
                    for line in content.splitlines():
                        if line.strip():
                            self.add_indicator(ThreatIndicator(**json.loads(line)))
            logger.info("Loaded external threat feed from %s", feed_path)
        except Exception as exc:
            logger.error("Failed to parse threat feed file %s: %s", feed_path, exc)

    def lookup_ioc(
        self,
        value: str,
        ioc_type: IOCTypeEnum | None = None,
    ) -> ThreatIndicator | None:
        """Lookup an IOC value with exact and CIDR matching."""
        normalized_val = value.strip().lower()

        # Step 1: Exact Match (if ioc_type specified, check directly; else search all types)
        if ioc_type:
            exact = self._exact_indicators.get((ioc_type, normalized_val))
            if exact:
                return exact
        else:
            for cand_type in [
                IOCTypeEnum.IP,
                IOCTypeEnum.DOMAIN,
                IOCTypeEnum.SHA256,
                IOCTypeEnum.MD5,
                IOCTypeEnum.URL,
            ]:
                exact = self._exact_indicators.get((cand_type, normalized_val))
                if exact:
                    return exact

        # Step 2: CIDR Match for IP queries
        if ioc_type in {IOCTypeEnum.IP, None}:
            try:
                ip_obj = ipaddress.ip_address(normalized_val)
                for net, ind in self._cidr_indicators:
                    if ip_obj in net:
                        return ind
            except ValueError:
                pass

        return None

    def get_indicators(self) -> list[ThreatIndicator]:
        """Return all indicators."""
        return list(self._exact_indicators.values()) + [
            ind for _, ind in self._cidr_indicators
        ]


class MockThreatIntelProvider(BaseThreatIntelProvider):
    """Mockable threat intel provider for unit testing custom feeds and simulated responses."""

    def __init__(self) -> None:
        self._indicators: dict[str, ThreatIndicator] = {}

    def add_mock_indicator(self, indicator: ThreatIndicator) -> None:
        """Inject a mock threat indicator dynamically."""
        self._indicators[indicator.ioc_value.strip().lower()] = indicator

    def clear(self) -> None:
        """Clear all mock indicators."""
        self._indicators.clear()

    def lookup_ioc(
        self,
        value: str,
        ioc_type: IOCTypeEnum | None = None,
    ) -> ThreatIndicator | None:
        normalized_val = value.strip().lower()
        ind = self._indicators.get(normalized_val)
        if ind and (ioc_type is None or ind.ioc_type == ioc_type):
            return ind
        return None

    def get_indicators(self) -> list[ThreatIndicator]:
        return list(self._indicators.values())


# ==============================================================================
# 2. Telemetry Collector
# ==============================================================================


class ThreatIntelMetrics:
    """Thread-safe telemetry collector for Threat Intelligence matching."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_scans: int = 0
        self._threats_detected: int = 0
        self._benign_scans: int = 0
        self._cache_hits: int = 0
        self._cache_misses: int = 0

    def record_scan(self, is_match: bool, is_cache_hit: bool) -> None:
        """Record the outcome of a threat scan."""
        with self._lock:
            self._total_scans += 1
            if is_match:
                self._threats_detected += 1
            else:
                self._benign_scans += 1

            if is_cache_hit:
                self._cache_hits += 1
            else:
                self._cache_misses += 1

    def get_snapshot(self) -> ThreatIntelMetricsSnapshot:
        """Generate an immutable point-in-time metrics snapshot."""
        with self._lock:
            rate = (
                (self._threats_detected / self._total_scans * 100.0)
                if self._total_scans > 0
                else 0.0
            )
            return ThreatIntelMetricsSnapshot(
                total_scans=self._total_scans,
                threats_detected=self._threats_detected,
                benign_scans=self._benign_scans,
                cache_hits=self._cache_hits,
                cache_misses=self._cache_misses,
                detection_rate_pct=round(rate, 2),
            )

    def reset(self) -> None:
        """Reset all counters to zero."""
        with self._lock:
            self._total_scans = 0
            self._threats_detected = 0
            self._benign_scans = 0
            self._cache_hits = 0
            self._cache_misses = 0


# Global singleton metrics collector
threat_intel_metrics = ThreatIntelMetrics()


# ==============================================================================
# 3. Threat Intel Matcher Engine
# ==============================================================================


class ThreatIntelMatcher:
    """High-performance, mockable threat intelligence correlation engine.

    Extracts multi-vector IOCs from events, evaluates against providers,
    utilizes in-memory LRU caching, and injects standardized security enrichment.
    """

    def __init__(
        self,
        providers: list[BaseThreatIntelProvider] | None = None,
        config: ThreatIntelConfig | None = None,
        metrics: ThreatIntelMetrics | None = None,
    ) -> None:
        self._config = config or ThreatIntelConfig(
            feed_path=settings.THREAT_INTEL_FEED_PATH,
            enabled=settings.THREAT_INTEL_ENABLED,
        )
        self._metrics = metrics or threat_intel_metrics
        self._providers: list[BaseThreatIntelProvider] = (
            providers
            if providers is not None
            else [LocalThreatIntelProvider(self._config.feed_path)]
        )
        self._cache_lock = threading.Lock()
        self._cache: LRUCache[str, ThreatIntelResult] = LRUCache(
            maxsize=self._config.cache_size
        )

    def add_provider(self, provider: BaseThreatIntelProvider) -> None:
        """Register an additional threat intelligence provider."""
        self._providers.append(provider)

    def _classify_ioc_type(self, value: str) -> IOCTypeEnum:
        """Infer IOC classification from string format heuristics."""
        clean_val = value.strip()
        # IP address check
        try:
            ipaddress.ip_address(clean_val)
            return IOCTypeEnum.IP
        except ValueError:
            pass

        # Hash checks
        if _RE_SHA256.match(clean_val):
            return IOCTypeEnum.SHA256
        if _RE_MD5.match(clean_val):
            return IOCTypeEnum.MD5

        # URL check
        if clean_val.startswith(("http://", "https://", "ftp://")):
            return IOCTypeEnum.URL

        return IOCTypeEnum.DOMAIN

    def match_ioc(
        self,
        value: str | None,
        ioc_type: IOCTypeEnum | None = None,
    ) -> ThreatIntelResult | None:
        """Evaluate an individual IOC string against configured threat feeds.

        Returns ThreatIntelResult or None if value is empty or disabled.
        """
        if not self._config.enabled or not value:
            return None

        clean_val = str(value).strip().strip("[]").lower()
        if not clean_val:
            return None

        # Strip port if IPv4
        if ":" in clean_val and clean_val.count(":") == 1:
            clean_val = clean_val.split(":")[0]

        inferred_type = ioc_type or self._classify_ioc_type(clean_val)
        cache_key = f"{inferred_type.value}:{clean_val}"

        # Check Cache
        with self._cache_lock:
            if cache_key in self._cache:
                cached_res: ThreatIntelResult = self._cache[cache_key]
                self._metrics.record_scan(
                    is_match=cached_res.is_match,
                    is_cache_hit=True,
                )
                return cached_res if cached_res.is_match else None

        # Query Providers
        matched_ind: ThreatIndicator | None = None
        for prov in self._providers:
            matched_ind = prov.lookup_ioc(clean_val, ioc_type=inferred_type)
            if matched_ind:
                break

        if matched_ind and matched_ind.confidence >= self._config.confidence_threshold:
            res = ThreatIntelResult(
                is_match=True,
                matched_ioc=clean_val,
                ioc_type=matched_ind.ioc_type,
                threat_name=matched_ind.threat_name,
                category=matched_ind.category,
                severity=matched_ind.severity,
                confidence=matched_ind.confidence,
                source_feed=matched_ind.source_feed,
                description=matched_ind.description,
            )
            with self._cache_lock:
                self._cache[cache_key] = res
            self._metrics.record_scan(is_match=True, is_cache_hit=False)
            return res

        # Cache clean / negative match to prevent re-querying
        clean_res = ThreatIntelResult(
            is_match=False,
            matched_ioc=clean_val,
            ioc_type=inferred_type,
        )
        with self._cache_lock:
            self._cache[cache_key] = clean_res
        self._metrics.record_scan(is_match=False, is_cache_hit=False)
        return None

    def match_event(self, event: UniversalLogEvent) -> list[ThreatIntelResult]:
        """Scan all candidate IOCs across event endpoints, domains, and attributes."""
        if not self._config.enabled:
            return []

        candidates: list[tuple[str | None, IOCTypeEnum | None]] = []

        # 1. Network endpoints
        if event.source and event.source.ip:
            candidates.append((event.source.ip, IOCTypeEnum.IP))
        if event.destination and event.destination.ip:
            candidates.append((event.destination.ip, IOCTypeEnum.IP))

        # 2. Hostnames / Domains
        if event.source and event.source.hostname:
            candidates.append((event.source.hostname, IOCTypeEnum.DOMAIN))
        if event.destination and event.destination.hostname:
            candidates.append((event.destination.hostname, IOCTypeEnum.DOMAIN))

        # 3. Attributes
        for key in ["domain", "host", "dst_host", "src_host"]:
            val = event.attributes.get(key)
            if val and isinstance(val, str):
                candidates.append((val, IOCTypeEnum.DOMAIN))

        for key in ["hash", "sha256", "file_hash", "malware_hash"]:
            val = event.attributes.get(key)
            if val and isinstance(val, str):
                candidates.append((val, IOCTypeEnum.SHA256))

        for key in ["md5", "md5_hash"]:
            val = event.attributes.get(key)
            if val and isinstance(val, str):
                candidates.append((val, IOCTypeEnum.MD5))

        matches: list[ThreatIntelResult] = []
        for val, ioc_t in candidates:
            if val:
                hit = self.match_ioc(val, ioc_type=ioc_t)
                if hit:
                    matches.append(hit)

        return matches

    def enrich_event(self, event: UniversalLogEvent) -> UniversalLogEvent:
        """Enrich UniversalLogEvent with threat intelligence correlation findings."""
        if not self._config.enabled:
            return event

        matches = self.match_event(event)
        if not matches:
            return event

        # Sort matches by highest confidence and severity
        best_match = max(matches, key=lambda m: (m.severity.value, m.confidence))

        updated_enrichment = (
            event.enrichment.model_copy()
            if event.enrichment
            else EnrichmentContext()
        )
        updated_enrichment.threat_match = True

        updated_security = (
            event.security.model_copy()
            if event.security
            else SecurityContext()
        )
        updated_security.threat_id = best_match.threat_name

        updated_attrs = dict(event.attributes)
        updated_attrs["threat_intel"] = best_match.model_dump()
        if len(matches) > 1:
            updated_attrs["threat_intel_matches"] = [m.model_dump() for m in matches]

        return event.model_copy(
            update={
                "enrichment": updated_enrichment,
                "security": updated_security,
                "attributes": updated_attrs,
            }
        )

    def enrich_parsed_result(self, result: ParsedResult) -> ParsedResult:
        """Scan candidate IOCs in ParsedResult and inject threat telemetry into attributes."""
        if not self._config.enabled:
            return result

        candidates: list[tuple[str | None, IOCTypeEnum | None]] = []
        if result.source and result.source.ip:
            candidates.append((result.source.ip, IOCTypeEnum.IP))
        if result.destination and result.destination.ip:
            candidates.append((result.destination.ip, IOCTypeEnum.IP))
        if result.source and result.source.hostname:
            candidates.append((result.source.hostname, IOCTypeEnum.DOMAIN))
        if result.destination and result.destination.hostname:
            candidates.append((result.destination.hostname, IOCTypeEnum.DOMAIN))

        for key in ["domain", "host", "hash", "sha256", "md5"]:
            val = result.attributes.get(key)
            if val and isinstance(val, str):
                candidates.append((val, None))

        matches: list[ThreatIntelResult] = []
        for val, ioc_t in candidates:
            if val:
                hit = self.match_ioc(val, ioc_type=ioc_t)
                if hit:
                    matches.append(hit)

        if not matches:
            return result

        best_match = max(matches, key=lambda m: (m.severity.value, m.confidence))
        updated_attrs = dict(result.attributes)
        updated_attrs["threat_match"] = True
        updated_attrs["threat_intel"] = best_match.model_dump()

        updated_security = (
            result.security.model_copy()
            if result.security
            else SecurityContext()
        )
        updated_security.threat_id = best_match.threat_name

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
        """Return the current number of cached IOCs."""
        with self._cache_lock:
            return len(self._cache)

    @property
    def metrics(self) -> ThreatIntelMetrics:
        """Access the threat intel metrics collector."""
        return self._metrics


# Default singleton instance
default_threat_intel_matcher = ThreatIntelMatcher()


def get_threat_intel_matcher() -> ThreatIntelMatcher:
    """Return the default ThreatIntelMatcher singleton instance."""
    return default_threat_intel_matcher
