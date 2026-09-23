# LogMorph

**Universal Log Pre-processing Framework** — A multi-tenant SaaS platform that automatically detects, parses, normalizes, cleans, and enriches heterogeneous log data from any source into a unified, analysis-ready schema.

## Features

- **Automatic Format Detection** — Identifies Syslog (RFC 3164/5424), JSON, CEF, LEEF, Apache CLF, XML, and unstructured text automatically.
- **3-Tier Adaptive Parsing Cascade** — Rule-based fast-path → Drain3 template mining → AI fallback (NVIDIA NIM) for maximum coverage.
- **Universal Log Schema (ULS)** — Normalizes all log formats into a single, consistent Pydantic-validated data model.
- **Data Quality Pipeline** — Timestamp normalization (ISO 8601 UTC), field sanitization, and sliding-window deduplication.
- **Contextual Enrichment** — GeoIP resolution, STIX2/MISP threat intelligence matching, and MITRE ATT&CK technique tagging.
- **Multi-Tenant SaaS** — User authentication, API key-based ingestion, and tenant-isolated log storage and querying.
- **Real-Time Dashboard** — React + TypeScript web interface for live log inspection, format statistics, and pipeline monitoring.

## Technology Stack

| Layer | Technology |
| :--- | :--- |
| Backend | Python 3.11+, FastAPI, AsyncIO |
| Database | NeonDB (Serverless PostgreSQL), SQLModel |
| Message Queue | Redis Streams (Upstash) |
| Authentication | JWT (PyJWT), API Key Auth |
| Log Parsing | Regex, Drain3, NVIDIA NIM API |
| Frontend | React, TypeScript, Tailwind CSS, Vite |
| Deployment | Render, Vercel |

## Getting Started

> Documentation will be added as the project develops.

## License

MIT
