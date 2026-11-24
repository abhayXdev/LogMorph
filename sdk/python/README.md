# LogMorph Python SDK

Zero-dependency, non-blocking telemetry and log ingestion client for the LogMorph platform.

## Features

- **Zero Dependencies**: Built entirely using the Python standard library (`urllib.request`, `json`, `threading`, `queue`).
- **Non-Blocking Architecture**: Log dispatches execute asynchronously on a background worker thread, ensuring zero latency impact on your core application.
- **Fail-Safe Design**: Network errors or backend timeouts degrade silently and never crash your application.
- **Standard Library Integration**: Native `logging.Handler` support to automatically stream existing `logging` statements.
- **Universal Compatibility**: Compatible with Python 3.8+ across Linux, macOS, Windows, containerized environments, and cloud functions.

## Installation

```bash
pip install logmorph
```

Or install directly from GitHub:

```bash
pip install git+https://github.com/abhaypaul058/MINIproject.git#subdirectory=sdk/python
```

## Quick Start

### 1. Direct Logging

```python
from logmorph import LogMorph

# Initialize client (uses https://logmorph.onrender.com by default)
client = LogMorph(
    api_key="lm_live_your_api_key_here",
    source="payment-service"
)

# Send structured or plain text logs
client.log("Checkout completed for order #8491", level="INFO")
client.log("Gateway timeout during capture", level="ERROR")

# Ensure all buffered logs are flushed before exit
client.flush()
```

### 2. Integration with Python's Standard `logging`

```python
import logging
from logmorph import LogMorphHandler

logger = logging.getLogger("my_app")
logger.setLevel(logging.INFO)

# Attach LogMorph handler
handler = LogMorphHandler(
    api_key="lm_live_your_api_key_here",
    source="backend-api"
)
logger.addHandler(handler)

# Standard logging calls stream directly to LogMorph
logger.info("Service initialized")
logger.warning("Cache miss for user profile")
logger.error("Database connection refused")
```

## Configuration Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `api_key` | `str` | *Required* | Your LogMorph project API key. |
| `endpoint` | `str` | `https://logmorph.onrender.com/api/v1/ingest` | Ingestion API URL. |
| `source` | `str` | `default` | Identifier for the sending service or node. |
| `max_buffer_size` | `int` | `1000` | Maximum logs held in queue before dropping oldest. |
| `timeout` | `float` | `2.0` | HTTP request timeout in seconds. |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
