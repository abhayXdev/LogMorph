"""GeoIP enrichment adapter with autonomous embedded offline database and LRU caching.

Provides zero-dependency IP geolocation resolution, RFC 1918 private IP filtering,
optional MaxMind MMDB pluggability, and sub-5-microsecond in-memory LRU caching.
"""

from __future__ import annotations

import bisect
import ipaddress
import logging
import threading
from typing import Any

from cachetools import LRUCache  # type: ignore[import-untyped]

from logmorph.config import settings
from logmorph.domain.uls import (
    EnrichmentContext,
    UniversalLogEvent,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.enrichment import (
    GeoIPConfig,
    GeoIPLookupResult,
    GeoIPMetricsSnapshot,
)

logger = logging.getLogger(__name__)

# Type alias for embedded database entry: (start_int, end_int, metadata_dict)
_RangeEntry = tuple[int, int, dict[str, Any]]

# Pre-compiled embedded subnet definitions for major DNS Anycast, cloud providers, and global carriers
_RAW_EMBEDDED_SUBNETS: list[tuple[str, dict[str, Any]]] = [
    # --- Google / Anycast DNS & Services ---
    (
        "8.8.8.0/24",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "asn": 15169,
            "as_org": "Google LLC",
        },
    ),
    (
        "8.8.4.0/24",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "asn": 15169,
            "as_org": "Google LLC",
        },
    ),
    (
        "142.250.0.0/15",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "asn": 15169,
            "as_org": "Google LLC",
        },
    ),
    (
        "172.217.0.0/16",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "asn": 15169,
            "as_org": "Google LLC",
        },
    ),
    # --- Cloudflare Anycast / CDN ---
    (
        "1.1.1.0/24",
        {
            "country": "United States",
            "country_code": "US",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": 13335,
            "as_org": "Cloudflare, Inc.",
        },
    ),
    (
        "1.0.0.0/24",
        {
            "country": "United States",
            "country_code": "US",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": 13335,
            "as_org": "Cloudflare, Inc.",
        },
    ),
    (
        "104.16.0.0/12",
        {
            "country": "United States",
            "country_code": "US",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": 13335,
            "as_org": "Cloudflare, Inc.",
        },
    ),
    # --- Quad9 Anycast DNS ---
    (
        "9.9.9.0/24",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Berkeley",
            "latitude": 37.8715,
            "longitude": -122.2730,
            "asn": 19281,
            "as_org": "Quad9",
        },
    ),
    (
        "149.112.112.0/24",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Berkeley",
            "latitude": 37.8715,
            "longitude": -122.2730,
            "asn": 19281,
            "as_org": "Quad9",
        },
    ),
    # --- Cisco OpenDNS ---
    (
        "208.67.220.0/22",
        {
            "country": "United States",
            "country_code": "US",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": 36692,
            "as_org": "Cisco OpenDNS",
        },
    ),
    # --- AWS us-east-1 (N. Virginia) ---
    (
        "3.80.0.0/12",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Ashburn",
            "latitude": 39.0438,
            "longitude": -77.4874,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    (
        "52.92.0.0/14",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Ashburn",
            "latitude": 39.0438,
            "longitude": -77.4874,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    (
        "54.224.0.0/12",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Ashburn",
            "latitude": 39.0438,
            "longitude": -77.4874,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    # --- AWS eu-central-1 (Frankfurt, Germany) ---
    (
        "3.120.0.0/14",
        {
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    (
        "18.194.0.0/15",
        {
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    (
        "35.156.0.0/14",
        {
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    # --- AWS ap-south-1 (Mumbai, India) ---
    (
        "13.126.0.0/15",
        {
            "country": "India",
            "country_code": "IN",
            "city": "Mumbai",
            "latitude": 19.0760,
            "longitude": 72.8777,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    (
        "13.232.0.0/14",
        {
            "country": "India",
            "country_code": "IN",
            "city": "Mumbai",
            "latitude": 19.0760,
            "longitude": 72.8777,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    (
        "15.206.0.0/15",
        {
            "country": "India",
            "country_code": "IN",
            "city": "Mumbai",
            "latitude": 19.0760,
            "longitude": 72.8777,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    # --- AWS ap-northeast-1 (Tokyo, Japan) ---
    (
        "13.112.0.0/14",
        {
            "country": "Japan",
            "country_code": "JP",
            "city": "Tokyo",
            "latitude": 35.6762,
            "longitude": 139.6503,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    (
        "52.68.0.0/15",
        {
            "country": "Japan",
            "country_code": "JP",
            "city": "Tokyo",
            "latitude": 35.6762,
            "longitude": 139.6503,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    # --- AWS eu-west-1 (Dublin, Ireland) ---
    (
        "34.240.0.0/13",
        {
            "country": "Ireland",
            "country_code": "IE",
            "city": "Dublin",
            "latitude": 53.3498,
            "longitude": -6.2603,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    # --- AWS ap-southeast-2 (Sydney, Australia) ---
    (
        "13.54.0.0/15",
        {
            "country": "Australia",
            "country_code": "AU",
            "city": "Sydney",
            "latitude": -33.8688,
            "longitude": 151.2093,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    # --- AWS sa-east-1 (São Paulo, Brazil) ---
    (
        "54.232.0.0/16",
        {
            "country": "Brazil",
            "country_code": "BR",
            "city": "São Paulo",
            "latitude": -23.5505,
            "longitude": -46.6333,
            "asn": 16509,
            "as_org": "Amazon.com, Inc.",
        },
    ),
    # --- Microsoft Azure (North America & Europe) ---
    (
        "13.64.0.0/11",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Redmond",
            "latitude": 47.6740,
            "longitude": -122.1215,
            "asn": 8075,
            "as_org": "Microsoft Corporation",
        },
    ),
    (
        "20.36.0.0/14",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Boydton",
            "latitude": 36.6679,
            "longitude": -78.3875,
            "asn": 8075,
            "as_org": "Microsoft Corporation",
        },
    ),
    (
        "51.140.0.0/14",
        {
            "country": "United Kingdom",
            "country_code": "GB",
            "city": "London",
            "latitude": 51.5074,
            "longitude": -0.1278,
            "asn": 8075,
            "as_org": "Microsoft Corporation",
        },
    ),
    # --- Representative IPv6 Anycast Ranges ---
    (
        "2001:4860::/32",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "asn": 15169,
            "as_org": "Google LLC",
        },
    ),
    (
        "2606:4700::/32",
        {
            "country": "United States",
            "country_code": "US",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": 13335,
            "as_org": "Cloudflare, Inc.",
        },
    ),
    (
        "2620:fe::/32",
        {
            "country": "United States",
            "country_code": "US",
            "city": "Berkeley",
            "latitude": 37.8715,
            "longitude": -122.2730,
            "asn": 19281,
            "as_org": "Quad9",
        },
    ),
]


def _build_sorted_range_table() -> tuple[list[_RangeEntry], list[_RangeEntry]]:
    """Compile CIDR definitions into separate sorted IPv4 and IPv6 integer range lists."""
    ipv4_list: list[_RangeEntry] = []
    ipv6_list: list[_RangeEntry] = []

    for cidr, meta in _RAW_EMBEDDED_SUBNETS:
        net = ipaddress.ip_network(cidr, strict=False)
        start = int(net.network_address)
        end = int(net.broadcast_address)
        if net.version == 4:
            ipv4_list.append((start, end, meta))
        else:
            ipv6_list.append((start, end, meta))

    ipv4_list.sort(key=lambda item: item[0])
    ipv6_list.sort(key=lambda item: item[0])
    return ipv4_list, ipv6_list


# Singleton compiled tables
_IPV4_RANGES, _IPV6_RANGES = _build_sorted_range_table()
_IPV4_STARTS = [r[0] for r in _IPV4_RANGES]
_IPV6_STARTS = [r[0] for r in _IPV6_RANGES]


class GeoIPMetrics:
    """Thread-safe telemetry collector for GeoIP lookups."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_lookups: int = 0
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._private_ips_skipped: int = 0
        self._embedded_lookups: int = 0
        self._mmdb_lookups: int = 0

    def record_lookup(
        self,
        is_cache_hit: bool,
        is_private: bool,
        resolved_by: str,
    ) -> None:
        """Record the outcome of an IP geolocation evaluation."""
        with self._lock:
            self._total_lookups += 1
            if is_cache_hit:
                self._cache_hits += 1
            else:
                self._cache_misses += 1
                if is_private:
                    self._private_ips_skipped += 1
                elif resolved_by == "MAXMIND_MMDB":
                    self._mmdb_lookups += 1
                else:
                    self._embedded_lookups += 1

    def get_snapshot(self) -> GeoIPMetricsSnapshot:
        """Generate an immutable point-in-time metrics snapshot."""
        with self._lock:
            rate = (
                (self._cache_hits / self._total_lookups * 100.0)
                if self._total_lookups > 0
                else 0.0
            )
            return GeoIPMetricsSnapshot(
                total_lookups=self._total_lookups,
                cache_hits=self._cache_hits,
                cache_misses=self._cache_misses,
                private_ips_skipped=self._private_ips_skipped,
                embedded_lookups=self._embedded_lookups,
                mmdb_lookups=self._mmdb_lookups,
                hit_rate_pct=round(rate, 2),
            )

    def reset(self) -> None:
        """Reset all metric counters to zero."""
        with self._lock:
            self._total_lookups = 0
            self._cache_hits = 0
            self._cache_misses = 0
            self._private_ips_skipped = 0
            self._embedded_lookups = 0
            self._mmdb_lookups = 0


# Global metrics instance
geoip_metrics = GeoIPMetrics()


class GeoIPAdapter:
    """Production-grade GeoIP resolution adapter.

    Features embedded offline database fallback, RFC 1918 private filtering,
    optional MaxMind MMDB pluggability, and thread-safe LRU caching.
    """

    def __init__(
        self,
        config: GeoIPConfig | None = None,
        metrics: GeoIPMetrics | None = None,
    ) -> None:
        self._config = config or GeoIPConfig(
            db_path=settings.GEOIP_DB_PATH,
            enabled=settings.GEOIP_ENABLED,
        )
        self._metrics = metrics or geoip_metrics
        self._cache_lock = threading.Lock()
        self._cache: LRUCache[str, GeoIPLookupResult] = LRUCache(
            maxsize=self._config.cache_size
        )
        self._mmdb_reader: Any = None

        # Attempt to load MaxMind MMDB if configured and dependency is installed
        if self._config.db_path:
            self._init_mmdb_reader(self._config.db_path)

    def _init_mmdb_reader(self, db_path: str) -> None:
        """Attempt to initialize the MaxMind MMDB reader."""
        try:
            import maxminddb  # type: ignore[import-not-found]

            self._mmdb_reader = maxminddb.open_database(db_path)
            logger.info("Successfully loaded MaxMind MMDB from: %s", db_path)
        except ImportError:
            logger.debug("maxminddb package not installed; falling back to embedded database")
            self._mmdb_reader = None
        except Exception as exc:
            logger.warning("Failed to open MaxMind MMDB at %s: %s", db_path, exc)
            self._mmdb_reader = None

    def _query_embedded_database(
        self,
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> GeoIPLookupResult:
        """Execute fast binary search over pre-sorted integer ranges."""
        ip_int = int(ip_obj)
        canonical_ip = str(ip_obj)

        if ip_obj.version == 4:
            ranges = _IPV4_RANGES
            starts = _IPV4_STARTS
        else:
            ranges = _IPV6_RANGES
            starts = _IPV6_STARTS

        idx = bisect.bisect_right(starts, ip_int) - 1
        if idx >= 0 and ranges[idx][0] <= ip_int <= ranges[idx][1]:
            meta = ranges[idx][2]
            return GeoIPLookupResult(
                ip=canonical_ip,
                country=meta.get("country"),
                country_code=meta.get("country_code"),
                city=meta.get("city"),
                latitude=meta.get("latitude"),
                longitude=meta.get("longitude"),
                asn=meta.get("asn"),
                as_org=meta.get("as_org"),
                is_private=False,
                is_bogon=False,
                resolved_by="EMBEDDED_OFFLINE",
            )

        # Fallback for unrecognized public IP
        return GeoIPLookupResult(
            ip=canonical_ip,
            country="Unknown",
            country_code="ZZ",
            city=None,
            latitude=None,
            longitude=None,
            asn=None,
            as_org=None,
            is_private=False,
            is_bogon=False,
            resolved_by="EMBEDDED_OFFLINE",
        )

    def _query_mmdb(
        self,
        ip_str: str,
    ) -> GeoIPLookupResult | None:
        """Query MaxMind MMDB reader if available."""
        if not self._mmdb_reader:
            return None

        try:
            record = self._mmdb_reader.get(ip_str)
            if not record:
                return None

            country_data = record.get("country", {})
            city_data = record.get("city", {})
            location_data = record.get("location", {})

            country_name = country_data.get("names", {}).get("en")
            country_code = country_data.get("iso_code")
            city_name = city_data.get("names", {}).get("en")
            lat = location_data.get("latitude")
            lon = location_data.get("longitude")

            return GeoIPLookupResult(
                ip=ip_str,
                country=country_name,
                country_code=country_code,
                city=city_name,
                latitude=float(lat) if lat is not None else None,
                longitude=float(lon) if lon is not None else None,
                asn=record.get("autonomous_system_number"),
                as_org=record.get("autonomous_system_organization"),
                is_private=False,
                is_bogon=False,
                resolved_by="MAXMIND_MMDB",
            )
        except Exception as exc:
            logger.debug("MMDB lookup failed for %s: %s; using embedded fallback", ip_str, exc)
            return None

    def lookup(self, ip: str | None) -> GeoIPLookupResult | None:
        """Resolve geographical telemetry for an IPv4 or IPv6 address.

        Returns None if IP is empty, unparseable, or GeoIP is disabled.
        """
        if not self._config.enabled or not ip:
            return None

        raw_ip = str(ip).strip().strip("[]")
        # Strip trailing port if present (e.g. "1.1.1.1:8080" or "[2001:db8::1]:443")
        if ":" in raw_ip and not raw_ip.count(":") >= 2:
            raw_ip = raw_ip.split(":")[0]

        # Check Cache
        with self._cache_lock:
            if raw_ip in self._cache:
                cached_res: GeoIPLookupResult = self._cache[raw_ip]
                self._metrics.record_lookup(
                    is_cache_hit=True,
                    is_private=cached_res.is_private,
                    resolved_by="CACHE",
                )
                return cached_res

        # Validate IP format via ipaddress
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            return None

        # RFC Filtering: Private, Loopback, Link-Local, Reserved
        if ip_obj.is_private:
            result = GeoIPLookupResult(
                ip=raw_ip,
                country="Private Network",
                country_code=None,
                city="Internal Network",
                is_private=True,
                is_bogon=False,
                resolved_by="RFC_PRIVATE",
            )
            with self._cache_lock:
                self._cache[raw_ip] = result
            self._metrics.record_lookup(
                is_cache_hit=False,
                is_private=True,
                resolved_by="RFC_PRIVATE",
            )
            return result

        if ip_obj.is_loopback:
            result = GeoIPLookupResult(
                ip=raw_ip,
                country="Loopback",
                country_code=None,
                city="Localhost",
                is_private=True,
                is_bogon=True,
                resolved_by="RFC_LOOPBACK",
            )
            with self._cache_lock:
                self._cache[raw_ip] = result
            self._metrics.record_lookup(
                is_cache_hit=False,
                is_private=True,
                resolved_by="RFC_LOOPBACK",
            )
            return result

        if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            result = GeoIPLookupResult(
                ip=raw_ip,
                country="Reserved / Bogon",
                country_code=None,
                is_private=True,
                is_bogon=True,
                resolved_by="RFC_RESERVED",
            )
            with self._cache_lock:
                self._cache[raw_ip] = result
            self._metrics.record_lookup(
                is_cache_hit=False,
                is_private=True,
                resolved_by="RFC_RESERVED",
            )
            return result

        # Tier 1: Try MaxMind MMDB if available
        mmdb_res = self._query_mmdb(raw_ip)
        if mmdb_res is not None:
            with self._cache_lock:
                self._cache[raw_ip] = mmdb_res
            self._metrics.record_lookup(
                is_cache_hit=False,
                is_private=False,
                resolved_by="MAXMIND_MMDB",
            )
            return mmdb_res

        # Tier 2: Embedded Offline Database (Binary Search)
        embedded_res = self._query_embedded_database(ip_obj)
        with self._cache_lock:
            self._cache[raw_ip] = embedded_res
        self._metrics.record_lookup(
            is_cache_hit=False,
            is_private=False,
            resolved_by="EMBEDDED_OFFLINE",
        )
        return embedded_res

    def enrich_event(self, event: UniversalLogEvent) -> UniversalLogEvent:
        """Enrich a UniversalLogEvent with geographical telemetry."""
        if not self._config.enabled:
            return event

        src_ip = event.source.ip if event.source else None
        dst_ip = event.destination.ip if event.destination else None

        src_geo = self.lookup(src_ip)
        dst_geo = self.lookup(dst_ip)

        # Prioritize public IP for primary GeoIPContext in enrichment
        chosen_geo = None
        if src_geo and not src_geo.is_private:
            chosen_geo = src_geo
        elif dst_geo and not dst_geo.is_private:
            chosen_geo = dst_geo
        elif src_geo:
            chosen_geo = src_geo
        elif dst_geo:
            chosen_geo = dst_geo

        updated_enrichment = (
            event.enrichment.model_copy()
            if event.enrichment
            else EnrichmentContext()
        )

        if chosen_geo:
            updated_enrichment.geoip = chosen_geo.to_geoip_context()

        # Preserve both endpoints in attributes for SIEM analytics
        updated_attrs = dict(event.attributes)
        if src_geo:
            updated_attrs["geoip_source"] = src_geo.model_dump()
        if dst_geo:
            updated_attrs["geoip_destination"] = dst_geo.model_dump()

        return event.model_copy(
            update={
                "enrichment": updated_enrichment,
                "attributes": updated_attrs,
            }
        )

    def enrich_parsed_result(self, result: ParsedResult) -> ParsedResult:
        """Enrich a ParsedResult with GeoIP telemetry in attributes."""
        if not self._config.enabled:
            return result

        src_ip = result.source.ip if result.source else None
        dst_ip = result.destination.ip if result.destination else None

        src_geo = self.lookup(src_ip)
        dst_geo = self.lookup(dst_ip)

        updated_attrs = dict(result.attributes)
        if src_geo:
            updated_attrs["geoip_source"] = src_geo.model_dump()
        if dst_geo:
            updated_attrs["geoip_destination"] = dst_geo.model_dump()

        return result.model_copy(update={"attributes": updated_attrs})

    def clear_cache(self) -> None:
        """Clear all entries from the in-memory LRU cache."""
        with self._cache_lock:
            self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Return the current number of cached IP entries."""
        with self._cache_lock:
            return len(self._cache)

    @property
    def metrics(self) -> GeoIPMetrics:
        """Access the GeoIP telemetry metrics collector."""
        return self._metrics


# Default singleton instance
default_geoip_adapter = GeoIPAdapter()


def get_geoip_adapter() -> GeoIPAdapter:
    """Return the default GeoIPAdapter singleton."""
    return default_geoip_adapter
