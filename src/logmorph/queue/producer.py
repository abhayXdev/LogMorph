"""Apache Kafka producer service with Aiven SSL and fallback buffering."""

import asyncio
import json
import logging
import os
import ssl
from typing import Any

from aiokafka import AIOKafkaProducer  # type: ignore[import-untyped]

from logmorph.config import settings
from logmorph.schemas.queue import RawLogMessage

logger = logging.getLogger(__name__)


class LogMorphKafkaProducer:
    """High-throughput asynchronous Kafka producer with multi-tenant partitioning.

    Supports Aiven Cloud mTLS SSL, SASL_SSL (SCRAM-SHA-256), standard PLAINTEXT,
    and graceful in-memory queue fallback for offline test resilience.
    """

    def __init__(self) -> None:
        self._producer: AIOKafkaProducer | None = None
        self._fallback_queue: asyncio.Queue[RawLogMessage] = asyncio.Queue()
        self._is_running: bool = False
        self._is_connected: bool = False

    @property
    def is_connected(self) -> bool:
        """Whether the producer is actively connected to the Kafka cluster."""
        return self._is_connected

    @property
    def fallback_queue(self) -> asyncio.Queue[RawLogMessage]:
        """Direct access to the fallback queue for inspection and draining."""
        return self._fallback_queue

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        """Construct SSLContext from certificate files or configured credentials."""
        if settings.KAFKA_SECURITY_PROTOCOL not in ("SSL", "SASL_SSL"):
            return None

        cafile = settings.KAFKA_SSL_CAFILE
        # Verify cafile exists on filesystem if configured
        if cafile and not os.path.exists(cafile):
            logger.warning("Configured KAFKA_SSL_CAFILE not found: %s", cafile)
            cafile = None

        ssl_context = ssl.create_default_context(cafile=cafile)

        # Check for mTLS client certificate and private key
        certfile = settings.KAFKA_SSL_CERTFILE
        keyfile = settings.KAFKA_SSL_KEYFILE
        if certfile and keyfile and os.path.exists(certfile) and os.path.exists(keyfile):
            ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            logger.info("Loaded client mTLS certificate chain from %s and %s", certfile, keyfile)

        return ssl_context

    async def start(self) -> None:
        """Initialize the Kafka producer connection pool."""
        if self._is_running:
            return

        self._is_running = True
        ssl_context = self._build_ssl_context()

        # Build producer kwargs conditionally
        producer_kwargs: dict[str, Any] = {
            "bootstrap_servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "security_protocol": settings.KAFKA_SECURITY_PROTOCOL,
            "value_serializer": lambda v: json.dumps(v, default=str).encode("utf-8"),
            "key_serializer": lambda k: k.encode("utf-8") if isinstance(k, str) else k,
            "request_timeout_ms": 5000,
            "ssl_context": ssl_context,
        }

        # Include SASL credentials if protocol requires SASL
        if "SASL" in settings.KAFKA_SECURITY_PROTOCOL:
            producer_kwargs["sasl_mechanism"] = settings.KAFKA_SASL_MECHANISM
            producer_kwargs["sasl_plain_username"] = settings.KAFKA_SASL_USERNAME
            producer_kwargs["sasl_plain_password"] = settings.KAFKA_SASL_PASSWORD

        try:
            self._producer = AIOKafkaProducer(**producer_kwargs)
            await self._producer.start()
            self._is_connected = True
            logger.info(
                "Connected to Apache Kafka broker at %s (%s)",
                settings.KAFKA_BOOTSTRAP_SERVERS,
                settings.KAFKA_SECURITY_PROTOCOL,
            )
        except Exception as e:
            logger.warning(
                "Failed to connect to Apache Kafka broker at %s: %s. "
                "Operating in resilient in-memory fallback queue mode.",
                settings.KAFKA_BOOTSTRAP_SERVERS,
                e,
            )
            self._is_connected = False
            self._producer = None

    async def stop(self) -> None:
        """Flush remaining messages and cleanly terminate connections."""
        self._is_running = False
        if self._producer and self._is_connected:
            try:
                await self._producer.stop()
                logger.info("Apache Kafka producer stopped cleanly.")
            except Exception as e:
                logger.error("Error shutting down Kafka producer: %s", e)
            finally:
                self._is_connected = False
                self._producer = None

    async def send_log(self, message: RawLogMessage) -> bool:
        """Publish a single log message partitioned by tenant_id.

        Args:
            message: Pydantic RawLogMessage envelope.

        Returns:
            True if successfully dispatched to broker or queued to fallback buffer.
        """
        payload = message.model_dump(mode="json")
        partition_key = str(message.tenant_id)

        if self._is_connected and self._producer:
            try:
                await self._producer.send_and_wait(
                    settings.KAFKA_TOPIC_RAW_LOGS,
                    key=partition_key,
                    value=payload,
                )
                return True
            except Exception as e:
                logger.warning(
                    "Kafka dispatch error (%s). Enqueueing message to fallback buffer.", e
                )

        # Fallback buffer when broker connection is inactive or fails
        await self._fallback_queue.put(message)
        return True

    async def send_batch(self, messages: list[RawLogMessage]) -> int:
        """Publish a batch of log messages partitioned by tenant_id.

        Args:
            messages: List of RawLogMessage envelopes.

        Returns:
            Count of successfully processed messages.
        """
        success_count = 0
        for msg in messages:
            sent = await self.send_log(msg)
            if sent:
                success_count += 1
        return success_count

    async def is_healthy(self) -> bool:
        """Probe broker status by checking topic metadata.

        Returns:
            True if broker is reachable and responds with topic metadata, False otherwise.
        """
        if not self._is_connected or not self._producer:
            return False

        try:
            partitions = await self._producer.partitions_for(settings.KAFKA_TOPIC_RAW_LOGS)
            return bool(partitions)
        except Exception:
            return False


# Module-level singleton
kafka_producer = LogMorphKafkaProducer()


async def get_kafka_producer() -> LogMorphKafkaProducer:
    """FastAPI dependency for accessing the active Kafka producer."""
    return kafka_producer
