"""Tier 2 Drain3 Template Mining Engine with Multi-Tenant Clustering."""

import asyncio
import ipaddress
import logging
import re
import threading
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse
from uuid import UUID

import cachetools  # type: ignore[import-untyped]
from drain3.file_persistence import FilePersistence  # type: ignore[import-untyped]
from drain3.masking import (  # type: ignore[import-untyped]
    AbstractMaskingInstruction,
    MaskingInstruction,
)
from drain3.persistence_handler import PersistenceHandler  # type: ignore[import-untyped]
from drain3.redis_persistence import RedisPersistence  # type: ignore[import-untyped]
from drain3.template_miner import TemplateMiner  # type: ignore[import-untyped]
from drain3.template_miner_config import TemplateMinerConfig  # type: ignore[import-untyped]

from logmorph.config import settings
from logmorph.domain.uls import (
    LogFormatEnum,
    ParsingTierEnum,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.parsers.base import ParsedResult

logger = logging.getLogger(__name__)

# Heuristic severity patterns for unstructured text
_SEVERITY_PATTERNS = [
    (re.compile(r"\b(fatal|critical|emerg|panic|oom-killer)\b", re.IGNORECASE), SeverityEnum.CRITICAL),
    (
        re.compile(
            r"\b(error|err|failed|failure|exception|nullpointerexception|timed\s*out|timeout|denied|connectionreseterror)\b",
            re.IGNORECASE,
        ),
        SeverityEnum.ERROR,
    ),
    (re.compile(r"\b(warn|warning)\b", re.IGNORECASE), SeverityEnum.WARNING),
    (re.compile(r"\b(notice)\b", re.IGNORECASE), SeverityEnum.NOTICE),
    (re.compile(r"\b(debug|trace)\b", re.IGNORECASE), SeverityEnum.DEBUG),
    (re.compile(r"\b(info|informational)\b", re.IGNORECASE), SeverityEnum.INFORMATIONAL),
]


def infer_severity(text: str) -> SeverityEnum:
    """Infer standardized severity level from unstructured error text using compiled heuristics."""
    for pattern, sev in _SEVERITY_PATTERNS:
        if pattern.search(text):
            return sev
    return SeverityEnum.INFORMATIONAL


def should_route_to_llm(result: ParsedResult) -> bool:
    """Tier 3 LLM hand-off gate: only novel valid logs (0.30 <= confidence < 0.70) route to LLM."""
    return result.success and (0.30 <= result.confidence < 0.70)


class ValidatedIPv6MaskingInstruction(AbstractMaskingInstruction):  # type: ignore[misc]
    """Drain3 masking instruction for IPv6 addresses (full and zero-compressed) with strict validation.

    Candidate regex uses boundary pattern handling leading colons (e.g. ::1), validated with
    ipaddress.ip_address() to eliminate false positives on timestamps or MAC addresses.
    """

    def __init__(self, mask_with: str = "IPV6") -> None:
        self.mask_with = mask_with
        self.regex = re.compile(
            r"(?:::1\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b)"
        )

    def mask(self, content: str, mask_prefix: str, mask_suffix: str) -> str:
        mask_token = mask_prefix + self.mask_with + mask_suffix

        def _repl(m: re.Match[str]) -> str:
            val = m.group(0)
            try:
                ip = ipaddress.ip_address(val)
                if ip.version == 6:
                    return mask_token
            except ValueError:
                pass
            return val

        return self.regex.sub(_repl, content)


class TenantMinerContext:
    """Encapsulates a tenant's TemplateMiner instance and its single synchronization lock."""

    def __init__(self, tenant_id: str, miner: TemplateMiner) -> None:
        self.tenant_id = tenant_id
        self.miner = miner
        self.lock = threading.RLock()
        self.is_loaded = False

    def load_sync(self) -> None:
        """Load persisted state synchronously under the tenant lock."""
        with self.lock:
            if self.miner.persistence_handler is not None:
                try:
                    self.miner.load_state()
                except Exception as e:
                    logger.warning("Failed loading state for tenant %s: %s", self.tenant_id, e)
            self.is_loaded = True

    def flush_sync(self, reason: str = "lru_eviction") -> None:
        """Flush state synchronously under the tenant lock."""
        with self.lock:
            if self.miner.persistence_handler is not None:
                try:
                    self.miner.save_state(reason)
                except Exception as e:
                    logger.warning("Failed saving state for tenant %s: %s", self.tenant_id, e)


class AsyncTenantMinerPool:
    """Thread-safe and async-compatible pool of tenant-isolated Drain3 miners with LRU eviction."""

    def __init__(
        self,
        max_active_tenants: int = 100,
        persistence_dir: Path | str | None = None,
        redis_enabled: bool = True,
    ) -> None:
        self._max_active_tenants = max_active_tenants
        self._persistence_dir = Path(persistence_dir) if persistence_dir else None
        self._redis_enabled = redis_enabled
        self._cache: cachetools.LRUCache[str, TenantMinerContext] = cachetools.LRUCache(
            maxsize=max_active_tenants
        )
        self._pool_lock = asyncio.Lock()
        self._sync_pool_lock = threading.RLock()

    def _build_miner_config(self) -> TemplateMinerConfig:
        config = TemplateMinerConfig()
        config.drain_max_clusters = 1000
        config.parametrize_numeric_tokens = True
        config.masking_instructions = [
            MaskingInstruction(
                r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
                "TIMESTAMP",
            ),
            MaskingInstruction(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP"),
            ValidatedIPv6MaskingInstruction("IPV6"),
            MaskingInstruction(
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
                "UUID",
            ),
            MaskingInstruction(r"\b0x[0-9a-fA-F]+\b", "HEX"),
            MaskingInstruction(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL"
            ),
            MaskingInstruction(r"(?<=[Pp][Oo][Rr][Tt][=:\s])\d{1,5}\b", "PORT"),
            MaskingInstruction(r"(?<=[sd]pt=)\d{1,5}\b", "PORT"),
        ]
        return config

    def _build_persistence_handler(self, tenant_id: str) -> PersistenceHandler | None:
        if self._redis_enabled and settings.REDIS_URL:
            try:
                u = urlparse(settings.REDIS_URL)
                host = u.hostname or "localhost"
                port = u.port or 6379
                db = int(u.path.lstrip("/") or "0")
                password = u.password
                is_ssl = u.scheme == "rediss"
                redis_key = f"drain3:{tenant_id}"
                handler = RedisPersistence(
                    redis_host=host,
                    redis_port=port,
                    redis_db=db,
                    redis_pass=password,
                    is_ssl=is_ssl,
                    redis_key=redis_key,
                )
                handler.r.ping()
                return handler
            except Exception as e:
                logger.debug(
                    "Redis persistence unavailable for tenant %s (%s); falling back to file/memory",
                    tenant_id,
                    e,
                )

        if self._persistence_dir:
            self._persistence_dir.mkdir(parents=True, exist_ok=True)
            return FilePersistence(str(self._persistence_dir / f"drain3_{tenant_id}.bin"))

        return None

    def _create_tenant_context(self, tenant_id: str) -> TenantMinerContext:
        config = self._build_miner_config()
        handler = self._build_persistence_handler(tenant_id)
        miner = TemplateMiner(persistence_handler=handler, config=config)
        return TenantMinerContext(tenant_id=tenant_id, miner=miner)

    async def get_or_create(self, tenant_id: str) -> TenantMinerContext:
        """Asynchronously retrieve or create tenant miner with non-blocking cold start and eviction."""
        async with self._pool_lock:
            if tenant_id in self._cache:
                ctx = cast(TenantMinerContext, self._cache[tenant_id])
                if not ctx.is_loaded:
                    await asyncio.to_thread(ctx.load_sync)
                return ctx

            # Evict LRU entry if cache is at capacity, flushing asynchronously
            if len(self._cache) >= self._max_active_tenants:
                lru_key = next(iter(self._cache))
                lru_ctx = cast(TenantMinerContext, self._cache.pop(lru_key))
                await asyncio.to_thread(lru_ctx.flush_sync, "lru_eviction")

            ctx = self._create_tenant_context(tenant_id)
            self._cache[tenant_id] = ctx
            await asyncio.to_thread(ctx.load_sync)
            return ctx

    def get_or_create_sync(self, tenant_id: str) -> TenantMinerContext:
        """Synchronously retrieve or create tenant miner."""
        with self._sync_pool_lock:
            if tenant_id in self._cache:
                ctx = cast(TenantMinerContext, self._cache[tenant_id])
                if not ctx.is_loaded:
                    ctx.load_sync()
                return ctx

            if len(self._cache) >= self._max_active_tenants:
                lru_key = next(iter(self._cache))
                lru_ctx = cast(TenantMinerContext, self._cache.pop(lru_key))
                lru_ctx.flush_sync("lru_eviction")

            ctx = self._create_tenant_context(tenant_id)
            self._cache[tenant_id] = ctx
            ctx.load_sync()
            return ctx


class DrainTemplateMiner:
    """Production Tier 2 Drain3 Template Mining Engine with Multi-Tenant Isolation."""

    def __init__(
        self,
        max_active_tenants: int = 100,
        persistence_dir: Path | str | None = None,
        redis_enabled: bool = True,
    ) -> None:
        self.pool = AsyncTenantMinerPool(
            max_active_tenants=max_active_tenants,
            persistence_dir=persistence_dir,
            redis_enabled=redis_enabled,
        )

    def parse(self, raw_log: str, tenant_id: UUID | str | None = None) -> ParsedResult:
        """Parse raw log line into a normalized ParsedResult using Drain3 template mining."""
        tid_str = str(tenant_id) if tenant_id is not None else "default"

        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.TEMPLATE,
                confidence=0.10,
                error_message="Empty raw log",
            )

        stripped = raw_log.strip()
        context = self.pool.get_or_create_sync(tid_str)

        with context.lock:
            res = context.miner.add_log_message(stripped)
            template = res["template_mined"]
            change_type = res["change_type"]
            cluster_id = res["cluster_id"]
            cluster_size = res["cluster_size"]
            cluster_count = res["cluster_count"]

            # Strict confidence precedence table
            if change_type == "none":
                confidence = 0.90 if cluster_size >= 2 else 0.50
            elif change_type == "cluster_template_changed":
                confidence = 0.75
            elif change_type == "cluster_created":
                confidence = 0.50
            else:
                confidence = 0.20

            # Extract dynamic parameters and masked entities
            params = context.miner.extract_parameters(template, stripped) or []
            parameters: list[str] = [p.value for p in params]
            masked_parameters: dict[str, str] = {
                p.mask_name: p.value for p in params if p.mask_name != "*"
            }

            # Map extracted entities to ULS domain schema
            src_ip = masked_parameters.get("IP") or masked_parameters.get("IPV6")
            src_port_str = masked_parameters.get("PORT")
            src_port = int(src_port_str) if src_port_str and src_port_str.isdigit() else None
            source = SourceInfo(ip=src_ip, port=src_port) if (src_ip or src_port) else None

            severity = infer_severity(stripped)
            raw_ts = masked_parameters.get("TIMESTAMP")

            attributes: dict[str, Any] = {
                "template": template,
                "cluster_id": cluster_id,
                "cluster_size": cluster_size,
                "cluster_count": cluster_count,
                "change_type": change_type,
                "confidence": confidence,
                "parameters": parameters,
                "masked_parameters": masked_parameters,
            }

            return ParsedResult(
                success=True,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.TEMPLATE,
                confidence=confidence,
                action="template_mined",
                raw_timestamp=raw_ts,
                severity=severity,
                source=source,
                attributes=attributes,
            )

    async def parse_async(self, raw_log: str, tenant_id: UUID | str | None = None) -> ParsedResult:
        """Asynchronously parse raw log line without event loop stalling on cold start."""
        tid_str = str(tenant_id) if tenant_id is not None else "default"

        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.TEMPLATE,
                confidence=0.10,
                error_message="Empty raw log",
            )

        stripped = raw_log.strip()
        context = await self.pool.get_or_create(tid_str)

        with context.lock:
            res = context.miner.add_log_message(stripped)
            template = res["template_mined"]
            change_type = res["change_type"]
            cluster_id = res["cluster_id"]
            cluster_size = res["cluster_size"]
            cluster_count = res["cluster_count"]

            if change_type == "none":
                confidence = 0.90 if cluster_size >= 2 else 0.50
            elif change_type == "cluster_template_changed":
                confidence = 0.75
            elif change_type == "cluster_created":
                confidence = 0.50
            else:
                confidence = 0.20

            params = context.miner.extract_parameters(template, stripped) or []
            parameters = [p.value for p in params]
            masked_parameters = {p.mask_name: p.value for p in params if p.mask_name != "*"}

            src_ip = masked_parameters.get("IP") or masked_parameters.get("IPV6")
            src_port_str = masked_parameters.get("PORT")
            src_port = int(src_port_str) if src_port_str and src_port_str.isdigit() else None
            source = SourceInfo(ip=src_ip, port=src_port) if (src_ip or src_port) else None

            severity = infer_severity(stripped)
            raw_ts = masked_parameters.get("TIMESTAMP")

            attributes = {
                "template": template,
                "cluster_id": cluster_id,
                "cluster_size": cluster_size,
                "cluster_count": cluster_count,
                "change_type": change_type,
                "confidence": confidence,
                "parameters": parameters,
                "masked_parameters": masked_parameters,
            }

            return ParsedResult(
                success=True,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.TEMPLATE,
                confidence=confidence,
                action="template_mined",
                raw_timestamp=raw_ts,
                severity=severity,
                source=source,
                attributes=attributes,
            )

    def inspect(self, raw_log: str, tenant_id: UUID | str | None = None) -> ParsedResult:
        """Strictly read-only inspection using miner.match().

        Structurally impossible to mutate cluster state or trigger persistence writes.
        """
        tid_str = str(tenant_id) if tenant_id is not None else "default"

        if not raw_log or not raw_log.strip():
            return ParsedResult(
                success=False,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.TEMPLATE,
                confidence=0.10,
                error_message="Empty raw log",
            )

        stripped = raw_log.strip()
        context = self.pool.get_or_create_sync(tid_str)

        with context.lock:
            # Read-only match against existing clusters
            cluster = context.miner.match(stripped)
            if cluster is None:
                return ParsedResult(
                    success=False,
                    format=LogFormatEnum.UNSTRUCTURED,
                    parsed_by=ParsingTierEnum.TEMPLATE,
                    confidence=0.20,
                    error_message="No matching cluster found in read-only inspection",
                )

            template = cluster.get_template()
            confidence = 0.90 if cluster.size >= 2 else 0.50
            params = context.miner.extract_parameters(template, stripped) or []
            parameters = [p.value for p in params]
            masked_parameters = {p.mask_name: p.value for p in params if p.mask_name != "*"}

            src_ip = masked_parameters.get("IP") or masked_parameters.get("IPV6")
            src_port_str = masked_parameters.get("PORT")
            src_port = int(src_port_str) if src_port_str and src_port_str.isdigit() else None
            source = SourceInfo(ip=src_ip, port=src_port) if (src_ip or src_port) else None

            severity = infer_severity(stripped)
            raw_ts = masked_parameters.get("TIMESTAMP")

            attributes = {
                "template": template,
                "cluster_id": cluster.cluster_id,
                "cluster_size": cluster.size,
                "cluster_count": len(context.miner.drain.id_to_cluster),
                "change_type": "none",
                "confidence": confidence,
                "parameters": parameters,
                "masked_parameters": masked_parameters,
            }

            return ParsedResult(
                success=True,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.TEMPLATE,
                confidence=confidence,
                action="template_mined",
                raw_timestamp=raw_ts,
                severity=severity,
                source=source,
                attributes=attributes,
            )


# Global singleton miner engine
_drain_miner = DrainTemplateMiner()


def parse_tier2(raw_log: str, tenant_id: UUID | str | None = None) -> ParsedResult:
    """Public synchronous entry point for Tier 2 Drain3 template mining."""
    return _drain_miner.parse(raw_log, tenant_id=tenant_id)


async def parse_tier2_async(raw_log: str, tenant_id: UUID | str | None = None) -> ParsedResult:
    """Public asynchronous entry point for Tier 2 Drain3 template mining."""
    return await _drain_miner.parse_async(raw_log, tenant_id=tenant_id)


def inspect_tier2(raw_log: str, tenant_id: UUID | str | None = None) -> ParsedResult:
    """Public read-only dry-run entry point (structurally non-mutating)."""
    return _drain_miner.inspect(raw_log, tenant_id=tenant_id)
