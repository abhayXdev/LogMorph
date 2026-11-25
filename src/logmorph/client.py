"""LogMorph Python SDK - Zero-dependency telemetry and log ingestion client.

Built strictly using Python standard library modules.
"""

from __future__ import annotations

import atexit
import contextlib
import json
import queue
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

_DEFAULT_ENDPOINT = "https://logmorph.onrender.com/api/v1/ingest"
_DEFAULT_SOURCE = "default"
_DEFAULT_BATCH_SIZE = 25
_DEFAULT_FLUSH_INTERVAL = 1.0
_DEFAULT_MAX_BUFFER_SIZE = 1000
_DEFAULT_TIMEOUT = 2.0


class LogMorph:
    """Non-blocking, zero-dependency telemetry client for LogMorph.

    Batches logs in an in-memory queue and dispatches them asynchronously
    on a background worker thread.
    """

    def __init__(
        self,
        api_key: str,
        endpoint: str = _DEFAULT_ENDPOINT,
        source: str = _DEFAULT_SOURCE,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        flush_interval: float = _DEFAULT_FLUSH_INTERVAL,
        max_buffer_size: int = _DEFAULT_MAX_BUFFER_SIZE,
        timeout: float = _DEFAULT_TIMEOUT,
        auto_start: bool = True,
    ) -> None:
        """Initialize the LogMorph client.

        Args:
            api_key: Project API key (e.g. 'lm_live_...').
            endpoint: Ingest endpoint URL.
            source: Source identifier for this client instance.
            batch_size: Maximum logs bundled in a single HTTP request.
            flush_interval: Maximum seconds to wait before flushing pending logs.
            max_buffer_size: Queue capacity limit to prevent memory bloat.
            timeout: HTTP request timeout in seconds.
            auto_start: Whether to immediately launch the background worker thread.
        """
        if not api_key or not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("api_key must be a non-empty string")

        self.api_key: str = api_key.strip()
        self.endpoint: str = endpoint.rstrip("/")
        self.source: str = source.strip() if source and source.strip() else _DEFAULT_SOURCE
        self.batch_size: int = max(1, batch_size)
        self.flush_interval: float = max(0.1, flush_interval)
        self.max_buffer_size: int = max(10, max_buffer_size)
        self.timeout: float = max(0.5, timeout)

        self._queue: queue.Queue[str] = queue.Queue(maxsize=self.max_buffer_size)
        self._shutdown_event = threading.Event()
        self._flush_trigger = threading.Event()
        self._worker_thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._is_closed = False

        if auto_start:
            self.start()

        atexit.register(self._atexit_handler)

    def start(self) -> None:
        """Start the background worker thread if not already running."""
        with self._lock:
            if self._is_closed:
                return
            if self._worker_thread is None or not self._worker_thread.is_alive():
                self._worker_thread = threading.Thread(
                    target=self._worker_loop,
                    name="LogMorphWorkerThread",
                    daemon=True,
                )
                self._worker_thread.start()

    def log(
        self,
        message: str | Mapping[str, Any] | Any,
        level: str = "INFO",
        **kwargs: Any,
    ) -> bool:
        """Enqueue a log message for background dispatch.

        This method is non-blocking and fail-safe; it will never raise
        an exception or crash the host application.

        Args:
            message: Raw log string, JSON-serializable dictionary, or arbitrary object.
            level: Severity label ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
            **kwargs: Additional metadata merged when message is a dictionary.

        Returns:
            bool: True if the log was accepted into the buffer, False otherwise.
        """
        if self._is_closed:
            return False

        try:
            formatted_log = self._format_message(message, level, kwargs)
            try:
                self._queue.put_nowait(formatted_log)
                return True
            except queue.Full:
                # Bounded queue protection: drop oldest item and push latest
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait(formatted_log)
                    return True
                except queue.Full:
                    return False
        except Exception:
            # Absolute fail-safe boundary
            return False

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until all queued logs have been dispatched or timeout expires.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            bool: True if the queue was fully drained, False if timed out.
        """
        if self._queue.empty():
            return True

        self._flush_trigger.set()
        start = time.time()
        while not self._queue.empty():
            if time.time() - start >= timeout:
                return False
            time.sleep(0.05)
        return True

    def close(self, timeout: float = 5.0) -> None:
        """Drain remaining logs and stop the background worker thread."""
        with self._lock:
            if self._is_closed:
                return
            self._is_closed = True

        self.flush(timeout=timeout)
        self._shutdown_event.set()
        self._flush_trigger.set()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def _atexit_handler(self) -> None:
        """Automatic cleanup callback triggered on process exit."""
        with contextlib.suppress(Exception):
            self.close(timeout=2.0)

    def _format_message(
        self,
        message: Any,
        level: str,
        extra: Mapping[str, Any],
    ) -> str:
        """Format input into a string or JSON payload."""
        if isinstance(message, Mapping):
            payload = dict(message)
            if "level" not in payload:
                payload["level"] = str(level).upper()
            if extra:
                payload.update(extra)
            return json.dumps(payload, default=str)
        if isinstance(message, str):
            return message
        try:
            return json.dumps(message, default=str)
        except Exception:
            return str(message)

    def _worker_loop(self) -> None:
        """Main loop of the background dispatch thread."""
        while not self._shutdown_event.is_set():
            batch: list[str] = []
            deadline = time.time() + self.flush_interval

            while len(batch) < self.batch_size and time.time() < deadline:
                remaining_time = max(0.01, deadline - time.time())
                try:
                    item = self._queue.get(timeout=remaining_time)
                    batch.append(item)
                    self._queue.task_done()
                except queue.Empty:
                    break

            if batch:
                self._dispatch_batch(batch)

            # Wait on flush trigger or timeout
            if self._flush_trigger.wait(timeout=0.05):
                self._flush_trigger.clear()

        # Final drain of remaining items upon shutdown
        drain_batch: list[str] = []
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                drain_batch.append(item)
                self._queue.task_done()
            except queue.Empty:
                break
        if drain_batch:
            self._dispatch_batch(drain_batch)

    def _dispatch_batch(self, batch: list[str]) -> None:
        """Send a batch of logs to the LogMorph ingestion API."""
        if not batch:
            return

        if len(batch) == 1:
            url = self.endpoint
            payload = {
                "raw_log": batch[0],
                "source": self.source,
            }
        else:
            url = f"{self.endpoint}/batch"
            payload = {
                "logs": batch,
                "source": self.source,
            }

        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url=url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key,
                    "User-Agent": "logmorph-python/0.1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                # 202 Accepted or 200 OK
                _ = resp.read()
        except Exception:
            # Fail-safe: do not crash caller; telemetry silently drops on network failure
            pass
