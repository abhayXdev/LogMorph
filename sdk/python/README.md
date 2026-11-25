# LogMorph Python SDK (`logmorph`)

[![PyPI Version](https://img.shields.io/badge/TestPyPI-v0.1.1-orange.svg?logo=pypi&logoColor=white)](https://test.pypi.org/project/logmorph/0.1.1/)
[![Python Versions](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg?logo=python&logoColor=white)](https://pypi.org/project/logmorph/)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20external-brightgreen.svg)](https://pypi.org/project/logmorph/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**The ultra-lightweight, zero-dependency telemetry client and logging handler for LogMorph.**

Engineered specifically for cloud microservices, serverless functions, containerized applications, and local scripts where minimal overhead, sub-second installation, and maximum reliability are essential.

---

## 🌟 Why LogMorph SDK?

* **Strict Zero External Dependencies**: Built 100% using the Python standard library (`urllib.request`, `json`, `threading`, `queue`, `atexit`). Zero supply-chain security risks, zero version conflicts, sub-second `pip install`.
* **Non-Blocking In-Memory Batching**: Your application never waits for network requests. Logs are placed into a bounded memory queue and dispatched asynchronously by a background daemon worker thread.
* **Bounded Buffer OOM Protection**: If an application error storm produces unexpected log bursts, the client drops the oldest records to strictly prevent memory exhaustion (`Out-Of-Memory`).
* **Fail-Safe Design**: Transient network drops, backend restarts, or DNS timeouts degrade silently and will **never** crash your core application.
* **Standard Library Integration**: Native `logging.Handler` subclass allows you to stream existing `logger.info()`, `logger.error()`, and `logger.exception()` statements with zero refactoring.
* **Dynamic Environment Configuration**: Supports seamless switching between local, staging, and cloud environments via `LOGMORPH_ENDPOINT` or `LOGMORPH_API_URL`.

---

## 📥 Installation

Install the package via pip:

```bash
pip install logmorph
```

*Or install from TestPyPI:*
```bash
pip install --index-url https://test.pypi.org/simple/ logmorph==0.1.1
```

---

## 🚀 Quick Start

### 1. Direct Telemetry Logging

```python
from logmorph import LogMorph

# Initialize client with your project API key
client = LogMorph(
    api_key="lm_live_your_api_key_here",
    source="payment-service",
)

# Send plain-text or structured JSON telemetry
client.log("Checkout transaction initiated", level="INFO")
client.log(
    {"event": "checkout_completed", "user_id": 841, "amount_usd": 129.50},
    level="INFO",
)

# Caught exceptions with stack context
try:
    calc = 100 / 0
except ZeroDivisionError as err:
    client.log(f"Calculation failed: {err}", level="ERROR")

# Flushes pending queue before application shutdown (also handled automatically on exit)
client.flush()
```

### 2. Integration with Python's Standard `logging` Module

```python
import logging
from logmorph import LogMorphHandler

# Configure your application logger
logger = logging.getLogger("api_gateway")
logger.setLevel(logging.INFO)

# Attach the LogMorph logging handler
handler = LogMorphHandler(
    api_key="lm_live_your_api_key_here",
    source="api-gateway",
)
logger.addHandler(handler)

# Your existing logging calls now stream directly to LogMorph in the background!
logger.info("Gateway service initialized on port 8080")
logger.warning("Rate limit threshold reached for IP 198.51.100.42")
logger.error("Database connection refused by upstream cluster")
```

---

## ⚙️ Configuration Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `api_key` | `str` | *Required* | Your LogMorph project API key (`lm_live_...`). |
| `endpoint` | `str` | Cloud Endpoint | Target ingestion URL. Defaults to `LOGMORPH_ENDPOINT` or `https://logmorph.onrender.com/api/v1/ingest`. |
| `source` | `str` | `"default"` | Identifier for the sending service, cluster, or node. |
| `batch_size` | `int` | `25` | Maximum number of logs bundled into a single HTTP POST request. |
| `flush_interval` | `float` | `1.0` | Maximum seconds to wait before dispatching buffered logs. |
| `max_buffer_size` | `int` | `1000` | Maximum logs queued in memory before dropping oldest messages. |
| `timeout` | `float` | `2.0` | HTTP request timeout in seconds. |

### Environment Variables
The client automatically inspects environment variables if parameters are omitted:
* `LOGMORPH_API_KEY`: Ingestion API key.
* `LOGMORPH_ENDPOINT`: Exact ingest endpoint URL (e.g. `https://my-domain.com/api/v1/ingest`).
* `LOGMORPH_API_URL`: Base server URL (e.g. `https://my-domain.com`).

---

## 🛡️ Legal Notice & Limitation of Liability

> [!IMPORTANT]
> **READ CAREFULLY PRIOR TO DISTRIBUTING OR INTEGRATING THIS LIBRARY.**

### 1. License & Warranty Disclaimer
This SDK is released under the **MIT License**. THE SOFTWARE IS PROVIDED **"AS IS"**, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NONINFRINGEMENT.

### 2. Limitation of Liability
IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING BUT NOT LIMITED TO LOSS OF DATA, REVENUE, PROFITS, APPLICATION DOWNTIME, OR DATA BREACHES) ARISING OUT OF THE USE OF OR INABILITY TO USE THIS CLIENT LIBRARY.

### 3. Data Privacy & Log Sanitization
Users are solely responsible for ensuring that log entries, arguments, exception messages, and payloads submitted to LogMorph do not expose sensitive personal information, unmasked credentials, private tokens, or regulated health records in violation of applicable data privacy legislation (including **GDPR**, **CCPA**, and **HIPAA**).

---

<div align="center">
  <sub>Copyright © 2026 Abhay Paul. Released under the MIT License.</sub>
</div>
