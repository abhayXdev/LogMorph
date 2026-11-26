# LogMorph Python SDK (`logmorph`)

[![PyPI version](https://img.shields.io/pypi/v/logmorph.svg?logo=pypi&logoColor=white)](https://pypi.org/project/logmorph/)
[![Python Versions](https://img.shields.io/pypi/pyversions/logmorph.svg?logo=python&logoColor=white)](https://pypi.org/project/logmorph/)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20external-brightgreen.svg)](https://pypi.org/project/logmorph/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Ultra-lightweight, zero-dependency telemetry client and logging handler for LogMorph.**

Engineered specifically for cloud microservices, serverless functions (AWS Lambda, Google Cloud Functions), containerized workloads (Docker, Kubernetes), and modern web backends (FastAPI, Flask, Django). Where minimal overhead, sub-second installation, and maximum reliability are essential, `logmorph` delivers enterprise log streaming with zero external bloat.

---

## 🌟 Key Features

* **Strict Zero External Dependencies**: Implemented entirely with the Python standard library (`urllib.request`, `json`, `threading`, `queue`, `atexit`). Zero supply-chain vulnerabilities, zero package conflicts, and near-instant `pip install`.
* **Non-Blocking Asynchronous Batching**: Your application never waits on network I/O. Logs are instantly placed into an internal memory queue and shipped in optimized micro-batches by a background daemon worker thread.
* **Bounded Buffer OOM Protection**: If an unexpected log storm occurs during network partition or downstream degradation, the client gracefully discards the oldest records to strictly prevent memory exhaustion (`Out-Of-Memory`).
* **Fail-Safe Operation**: Transient network drops, DNS timeouts, or backend restarts degrade silently without crashing or interrupting your application execution.
* **Drop-in Standard Logging Integration**: Includes a native `logging.Handler` subclass (`LogMorphHandler`) allowing you to stream existing `logger.info()`, `logger.warning()`, and `logger.error()` calls with two lines of code.
* **Dynamic Environment Configuration**: Seamlessly configure target ingestion endpoints and API credentials via constructor parameters or standard environment variables (`LOGMORPH_API_KEY`, `LOGMORPH_ENDPOINT`, `LOGMORPH_API_URL`).

---

## 📥 Installation

Install the official package from [PyPI](https://pypi.org/project/logmorph/):

```bash
pip install logmorph
```

To upgrade an existing installation:

```bash
pip install --upgrade logmorph
```

---

## 🚀 Quick Start

### 1. Direct Telemetry Logging (`LogMorph`)

Ideal for microservices, scripts, and standalone applications sending direct event payloads:

```python
from logmorph import LogMorph

# 1. Initialize client with your project API key
client = LogMorph(
    api_key="lm_live_your_api_key_here",
    source="payment-service",
)

# 2. Ship plain-text messages
client.log("Order checkout initiated", level="INFO")

# 3. Ship structured telemetry dictionaries
client.log(
    {
        "event": "payment_authorized",
        "order_id": "ORD-94821",
        "amount_usd": 149.99,
        "currency": "USD",
        "latency_ms": 42.8,
    },
    level="INFO",
)

# 4. Ship captured exceptions
try:
    result = 100 / 0
except ZeroDivisionError as err:
    client.log(f"Payment gateway calculation failed: {err}", level="ERROR")

# 5. Flush pending queue on demand (also handled automatically upon script exit)
client.flush()
```

---

### 2. Standard Python `logging` Integration (`LogMorphHandler`)

Seamlessly stream logs from existing Python codebases without altering logging statements:

```python
import logging
from logmorph import LogMorphHandler

# 1. Obtain your standard Python logger
logger = logging.getLogger("api_service")
logger.setLevel(logging.INFO)

# 2. Attach the LogMorph handler
handler = LogMorphHandler(
    api_key="lm_live_your_api_key_here",
    source="api-service",
)
logger.addHandler(handler)

# 3. Your standard logs now stream directly to LogMorph in the background!
logger.info("API gateway started on port 8080")
logger.warning("Upstream rate-limit approaching threshold")
logger.error("Database connection refused by replica pool")
```

---

### 3. Web Framework Integration (FastAPI / Flask)

Easily integrate LogMorph into web applications to capture incoming request telemetry:

```python
from fastapi import FastAPI, Request
from logmorph import LogMorph
import time

app = FastAPI(title="Order API")
telemetry = LogMorph(source="order-api")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    
    telemetry.log(
        {
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
        level="INFO" if response.status_code < 400 else "ERROR",
    )
    return response
```

---

## ⚙️ Configuration Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `api_key` | `str` | *Required* | LogMorph project API key (`lm_live_...`). Can be set via `LOGMORPH_API_KEY`. |
| `endpoint` | `str` | Cloud Ingestion URL | Target ingestion endpoint URL. Defaults to `LOGMORPH_ENDPOINT` or `https://logmorph.onrender.com/api/v1/ingest`. |
| `source` | `str` | `"default"` | Identifier for the sending service, cluster, host, or container. |
| `batch_size` | `int` | `25` | Maximum number of log records bundled into a single HTTP POST request. |
| `flush_interval` | `float` | `1.0` | Maximum seconds to wait before dispatching buffered log records. |
| `max_buffer_size` | `int` | `1000` | Maximum records retained in memory queue before dropping oldest items on backpressure. |
| `timeout` | `float` | `2.0` | HTTP request network timeout in seconds. |

### Environment Variables

If constructor parameters are omitted, the SDK automatically reads from system environment variables:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `LOGMORPH_API_KEY` | Ingestion API key | `lm_live_a1b2c3d4...` |
| `LOGMORPH_ENDPOINT` | Direct ingestion endpoint URL | `https://logmorph.onrender.com/api/v1/ingest` |
| `LOGMORPH_API_URL` | Base API host URL | `https://logmorph.onrender.com` |

---

## 🏗️ Architecture & Reliability Guarantees

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Application                       │
│                                                             │
│   client.log(...)       OR       logger.info(...)           │
└─────────────┬───────────────────────────┬───────────────────┘
              │                           │
              ▼                           ▼
      [ Non-Blocking ]            [ LogMorphHandler ]
      [ In-Memory Q  ] ◄──────────[  Record Mapper  ]
      (Max: 1000 items)
              │
              │  (Asynchronous Daemon Worker Thread)
              ▼
      [ Batch Aggregator ]
      (25 items or 1.0s timeout)
              │
              ▼  (HTTP POST / JSON via urllib)
┌─────────────────────────────────────────────────────────────┐
│                 LogMorph Ingestion Server                   │
│             (Live Ingest & Parsing Pipeline)                │
└─────────────────────────────────────────────────────────────┘
```

1. **Zero Impact on Latency**: Log insertion into the internal queue takes microsecond-level execution time. Network transport is 100% offloaded to a background daemon thread.
2. **Backpressure Safety**: If downstream networks fail, memory consumption remains strictly capped at `max_buffer_size`. The SDK never crashes your application with out-of-memory errors.
3. **Clean Shutdown**: Registers an `atexit` hook to flush remaining buffered records cleanly when the host process terminates.

---

## 🛡️ Legal Notice & Compliance

> **IMPORTANT NOTICE: PLEASE READ CAREFULLY PRIOR TO DEPLOYMENT.**

### 1. License & Warranty Disclaimer
This software is distributed under the **MIT License**. THE SOFTWARE IS PROVIDED **"AS IS"**, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NONINFRINGEMENT.

### 2. Limitation of Liability
IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. THIS INCLUDES, WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES (INCLUDING LOSS OF PROFITS, DATA CORRUPTION, SERVICE DOWNTIME, OR REGULATORY PENALTIES).

### 3. Data Privacy & Log Sanitization Advisory
Users and organizations utilizing this SDK are solely responsible for ensuring that log entries, arguments, exception traces, and telemetry payloads do not expose sensitive Personally Identifiable Information (PII), unmasked credentials, private cryptographic keys, or regulated health data in violation of applicable data privacy regulations, including but not limited to the **General Data Protection Regulation (GDPR)**, **California Consumer Privacy Act (CCPA)**, and the **Health Insurance Portability and Accountability Act (HIPAA)**.

---

## 🔗 Useful Links

* **Live Dashboard & API**: [https://logmorph.onrender.com](https://logmorph.onrender.com)
* **GitHub Repository**: [https://github.com/abhayXdev/LogMorph](https://github.com/abhayXdev/LogMorph)
* **Issue Tracker**: [https://github.com/abhayXdev/LogMorph/issues](https://github.com/abhayXdev/LogMorph/issues)
* **PyPI Package**: [https://pypi.org/project/logmorph/](https://pypi.org/project/logmorph/)

---

<div align="center">
  <sub>Copyright © 2026 abhayXdev. Licensed under the MIT License.</sub>
</div>
