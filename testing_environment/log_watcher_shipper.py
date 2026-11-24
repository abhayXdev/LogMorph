"""Real-Time Log File Watcher & Automated Event Shipper Service.

Continuously monitors a designated local log file, detects new appended log entries,
and immediately dispatches them to the LogMorph Ingestion API.
Features:
- Byte-offset file tracking (tailing) to avoid redundant reads.
- Robust HTTP retry on network drops and 502/503/504 cold-starts.
- Accurate change detection telemetry and per-event transmission logs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

def load_env(env_path: Path) -> dict[str, str]:
    config: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

CURRENT_DIR = Path(__file__).resolve().parent
ENV_CONFIG = load_env(CURRENT_DIR / ".env")

API_URL = ENV_CONFIG.get("LOGMORPH_API_URL", "https://logmorph.onrender.com").rstrip("/")
API_KEY = ENV_CONFIG.get("LOGMORPH_API_KEY", "")
SOURCE_NAME = ENV_CONFIG.get("LOGMORPH_SOURCE_NAME", "Telemetry-Server-Node")
DEFAULT_LOG_FILE = Path(ENV_CONFIG.get("LOG_FILE_PATH", "./server.log"))
POLL_INTERVAL = float(ENV_CONFIG.get("WATCHER_POLL_INTERVAL_SEC", "1.0"))

class LogWatcherShipper:
    def __init__(self, log_path: Path, api_url: str, api_key: str, source_name: str) -> None:
        self.log_path = log_path
        self.api_url = api_url
        self.api_key = api_key
        self.source_name = source_name
        self.last_offset = 0
        self.stats = {
            "detected": 0,
            "pushed": 0,
            "failed": 0,
            "bytes_pushed": 0,
        }

    def push_log_event(self, raw_log: str) -> dict | None:
        """Transmit detected log event to LogMorph Ingestion API."""
        endpoint = f"{self.api_url}/api/v1/ingest"
        payload = json.dumps({
            "raw_log": raw_log.strip(),
            "source": self.source_name,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "X-API-Key": self.api_key,
        }

        req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")

        # Retry up to 3 times on transient network failures
        for attempt in range(3):
            start = time.perf_counter()
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    body = json.loads(resp.read().decode("utf-8"))
                    self.stats["pushed"] += 1
                    self.stats["bytes_pushed"] += len(payload)
                    print(
                        f"[LogWatcher] PUSHED event -> ID: {body.get('event_id')} "
                        f"({elapsed_ms:.1f}ms | Source: '{self.source_name}')"
                    )
                    return body
            except urllib.error.HTTPError as e:
                err_text = e.read().decode("utf-8", errors="replace")
                print(f"[LogWatcher] HTTP Error {e.code}: {err_text}")
                if e.code not in [502, 503, 504]:
                    break
            except Exception as e:
                print(f"[LogWatcher] Network Error (attempt {attempt+1}/3): {e}")

            time.sleep(1.5 * (attempt + 1))

        self.stats["failed"] += 1
        return None

    def watch(self, start_at_end: bool = True, max_events: int | None = None) -> None:
        """Continuously monitor the target log file and ship newly detected entries."""
        print(f"[LogWatcher] Initializing monitor on file: '{self.log_path.resolve()}'")
        print(f"[LogWatcher] Destination API: {self.api_url}/api/v1/ingest")
        print(f"[LogWatcher] Bound Source Node: '{self.source_name}'")

        if not self.api_key:
            print("[LogWatcher] ERROR: LOGMORPH_API_KEY is not configured in .env. Exiting.")
            sys.exit(1)

        # Wait for file creation if it doesn't exist yet
        while not self.log_path.exists():
            print(f"[LogWatcher] Waiting for log file '{self.log_path.name}' to be created...")
            time.sleep(1.0)

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            if start_at_end:
                f.seek(0, os.SEEK_END)
            self.last_offset = f.tell()
            print(f"[LogWatcher] Active monitoring started at file offset {self.last_offset} bytes.")

            while True:
                line = f.readline()
                if line:
                    stripped = line.strip()
                    if stripped:
                        self.stats["detected"] += 1
                        print(f"\n[LogWatcher] DETECTED new log line [{self.stats['detected']}]:")
                        print(f"  └── {stripped[:100]}...")
                        self.push_log_event(stripped)

                        if max_events and self.stats["detected"] >= max_events:
                            print(f"[LogWatcher] Reached target limit of {max_events} events. Stopping.")
                            break
                else:
                    # No new line; check if file was truncated/rotated
                    current_size = self.log_path.stat().st_size
                    if current_size < self.last_offset:
                        print("[LogWatcher] File truncation/rotation detected. Resetting offset to 0.")
                        f.seek(0, os.SEEK_SET)
                    time.sleep(POLL_INTERVAL)

                self.last_offset = f.tell()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log File Watcher & Automated Ingestion Shipper")
    parser.add_argument("--file", type=Path, default=DEFAULT_LOG_FILE, help="Log file to monitor")
    parser.add_argument("--from-start", action="store_true", help="Process existing file content from offset 0")
    parser.add_argument("--max", type=int, default=None, help="Stop after shipping N events")
    args = parser.parse_args()

    shipper = LogWatcherShipper(
        log_path=args.file,
        api_url=API_URL,
        api_key=API_KEY,
        source_name=SOURCE_NAME,
    )
    shipper.watch(start_at_end=not args.from_start, max_events=args.max)
