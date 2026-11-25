"""Python standard library logging handler for LogMorph."""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from logmorph.client import LogMorph


class LogMorphHandler(logging.Handler):
    """A standard logging.Handler that forwards log records to LogMorph."""

    def __init__(
        self,
        api_key: str | None = None,
        client: LogMorph | None = None,
        level: int | str = logging.INFO,
        source: str = "default",
        endpoint: str = "https://logmorph.onrender.com/api/v1/ingest",
        **kwargs: Any,
    ) -> None:
        """Initialize the LogMorphHandler.

        Args:
            api_key: LogMorph API key (required if client is not provided).
            client: Optional pre-configured LogMorph client instance.
            level: Logging level threshold (default INFO).
            source: Source identifier for logs emitted by this handler.
            endpoint: LogMorph ingestion endpoint.
            **kwargs: Extra parameters passed to LogMorph client if created here.
        """
        super().__init__(level=level)

        if client is not None:
            self.client = client
        elif api_key is not None:
            self.client = LogMorph(
                api_key=api_key,
                source=source,
                endpoint=endpoint,
                **kwargs,
            )
        else:
            raise ValueError("Either 'api_key' or an existing 'client' must be provided.")

    def emit(self, record: logging.LogRecord) -> None:
        """Process and dispatch a logging record to LogMorph."""
        try:
            msg = self.format(record)
            self.client.log(
                message=msg,
                level=record.levelname,
            )
        except Exception:
            self.handleError(record)

    def flush(self) -> None:
        """Flush the underlying LogMorph client queue."""
        with contextlib.suppress(Exception):
            self.client.flush()

    def close(self) -> None:
        """Close the handler and drain the underlying LogMorph client."""
        with contextlib.suppress(Exception):
            self.client.close()
        super().close()
