"""Production Server Log Generator Simulator.

Simulates an active Linux server writing continuous telemetry events to a local log file.
Generates RFC 5424 Syslog, authentication events, sudo invocations,
database transactions, and lock state transitions.
"""

from __future__ import annotations

import argparse
import datetime
import os
import random
import time
from pathlib import Path

# Load settings from .env if present
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
DEFAULT_LOG_FILE = Path(ENV_CONFIG.get("LOG_FILE_PATH", "./server.log"))
DEFAULT_INTERVAL = float(ENV_CONFIG.get("LOG_GENERATION_INTERVAL_SEC", "3.0"))

HOSTNAMES = ["srv-app-01", "srv-db-primary", "srv-auth-bastion", "srv-edge-gw"]
PROCESS_NAMES = ["sshd", "kernel", "sudo", "lock_manager", "postgres", "nginx"]

LOG_TEMPLATES = [
    # Syslog Auth failure
    "<34>1 {iso_time} {host} sshd {pid} ID47 - Failed password for invalid user admin from {ip} port {port} ssh2",
    # Syslog Auth accepted
    "<38>1 {iso_time} {host} sshd {pid} - - Accepted publickey for deployer from {ip} port {port} ssh2",
    # Sudo privileged command execution
    "<85>1 {iso_time} {host} sudo {pid} - - deployer : TTY=pts/0 ; PWD=/etc/nginx ; USER=root ; COMMAND=/bin/systemctl reload nginx",
    # Database resource lock state transition
    "<134>1 {iso_time} {host} lock_manager {pid} - - Resource {resource} transition to status=LOCKED by tx_{tx_id}",
    "<134>1 {iso_time} {host} lock_manager {pid} - - Resource {resource} transition to status=UNLOCKED by tx_{tx_id}",
    # Firewall packet filter
    "<13>1 {iso_time} {host} kernel - - [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:xx SRC={ip} DST=10.0.0.5 PROTO=TCP SPT={port} DPT=22",
    # Database query error
    "<11>1 {iso_time} {host} postgres {pid} - - [ERROR] canceling statement due to statement timeout after 5002ms: SELECT * FROM orders WHERE status='PENDING'",
]

def generate_sample_log(sequence_number: int) -> str:
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    iso_time = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    host = random.choice(HOSTNAMES)
    pid = random.randint(1000, 65535)
    ip = f"{random.randint(11, 210)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    port = random.randint(1024, 65535)
    resource = random.choice(["table_payments", "table_orders", "vault_secrets", "session_store"])
    tx_id = random.randint(10000, 99999)

    template = random.choice(LOG_TEMPLATES)
    log_line = template.format(
        iso_time=iso_time,
        host=host,
        pid=pid,
        ip=ip,
        port=port,
        resource=resource,
        tx_id=tx_id,
    )
    return f"{log_line} seq={sequence_number}"

def run_generator(log_file: Path, interval: float, max_logs: int | None = None) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    print(f"[LogGenerator] Starting periodic generation -> '{log_file.resolve()}'")
    print(f"[LogGenerator] Interval: {interval}s | Max logs: {max_logs or 'Infinite'}")

    count = 0
    with open(log_file, "a", encoding="utf-8") as f:
        while True:
            count += 1
            entry = generate_sample_log(count)
            f.write(entry + "\n")
            f.flush()
            print(f"[LogGenerator] Generated [{count}]: {entry[:95]}...")

            if max_logs and count >= max_logs:
                print(f"[LogGenerator] Completed generating {count} logs.")
                break

            time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Continuous Log Generator")
    parser.add_argument("--file", type=Path, default=DEFAULT_LOG_FILE, help="Target log file path")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Seconds between logs")
    parser.add_argument("--count", type=int, default=None, help="Stop after generating N logs")
    args = parser.parse_args()

    run_generator(args.file, args.interval, args.count)
