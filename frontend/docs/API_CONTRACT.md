# LogMorph — API Contract for Frontend

> This document lists **every backend API endpoint** the frontend will call.
> Each endpoint includes the URL, HTTP method, headers, request body, and
> response body with realistic JSON examples.
>
> **Base URL (local dev):** `http://localhost:8000`
> **Base URL (production):** `https://logmorph-api.onrender.com` (TBD)

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [API Key Management](#2-api-key-management)
3. [Log Ingestion](#3-log-ingestion)
4. [Sandbox / Live Demo](#4-sandbox--live-demo)
5. [Log Events & Search](#5-log-events--search)
6. [Analytics & Stats](#6-analytics--stats)
7. [Log Sources](#7-log-sources)
8. [System Health](#8-system-health)

---

## 1. Authentication

All auth endpoints return a **JWT token**. Store it in `localStorage` or a
cookie. Send it in every subsequent request as:
```
Authorization: Bearer <jwt_token>
```

### POST `/auth/signup`

Create a new user account.

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "SecureP@ss123",
  "full_name": "Alice Johnson"
}
```

**Response (201 Created):**
```json
{
  "id": "usr_a1b2c3d4",
  "email": "alice@example.com",
  "full_name": "Alice Johnson",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "token_type": "bearer"
}
```

**Errors:**
| Status | Meaning |
| :--- | :--- |
| 409 | Email already registered |
| 422 | Validation error (weak password, invalid email) |

---

### POST `/auth/login`

Login with existing credentials.

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "SecureP@ss123"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "token_type": "bearer",
  "user": {
    "id": "usr_a1b2c3d4",
    "email": "alice@example.com",
    "full_name": "Alice Johnson"
  }
}
```

**Errors:**
| Status | Meaning |
| :--- | :--- |
| 401 | Wrong email or password |

---

### GET `/auth/me`

Get the currently logged-in user's profile.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "id": "usr_a1b2c3d4",
  "email": "alice@example.com",
  "full_name": "Alice Johnson",
  "created_at": "2026-09-20T14:30:00Z"
}
```

**Errors:**
| Status | Meaning |
| :--- | :--- |
| 401 | Token expired or invalid |

---

### POST `/auth/refresh`

Get a new JWT token using the current (soon-to-expire) token.

**Headers:** `Authorization: Bearer <old_jwt_token>`

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "token_type": "bearer"
}
```

---

## 2. API Key Management

These are the keys that external systems use to send logs to LogMorph.
The user manages these keys from the dashboard.

### POST `/api/v1/keys`

Generate a new API key.

**Headers:** `Authorization: Bearer <jwt_token>`

**Request:**
```json
{
  "name": "Production Firewall"
}
```

**Response (201 Created):**
```json
{
  "id": "key_x7y8z9",
  "name": "Production Firewall",
  "key": "lm_live_4f8a2b9c7d1e6f3a8b5c2d9e7f1a3b6c",
  "created_at": "2026-09-23T10:00:00Z",
  "is_active": true
}
```

> ⚠️ **Important:** The full `key` value is shown **only once** at creation time.
> The frontend must display a "Copy to clipboard" button and warn the user
> to save it. After this response, the backend only stores a hash of the key.

---

### GET `/api/v1/keys`

List all API keys for the current user.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "keys": [
    {
      "id": "key_x7y8z9",
      "name": "Production Firewall",
      "key_prefix": "lm_live_4f8a****",
      "created_at": "2026-09-23T10:00:00Z",
      "is_active": true,
      "last_used_at": "2026-09-23T18:45:00Z"
    },
    {
      "id": "key_m3n4o5",
      "name": "AWS CloudTrail",
      "key_prefix": "lm_live_9c2d****",
      "created_at": "2026-09-22T08:00:00Z",
      "is_active": true,
      "last_used_at": null
    }
  ]
}
```

> Note: `key_prefix` shows only the first 12 characters. The full key is never
> returned after creation.

---

### DELETE `/api/v1/keys/{key_id}`

Revoke (permanently disable) an API key.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "message": "API key revoked successfully",
  "id": "key_x7y8z9"
}
```

---

## 3. Log Ingestion

> 🔒 These endpoints use **API Key authentication**, not JWT.
> The frontend does NOT call these directly — external systems do.
> But you should understand them so you can show usage examples in the dashboard.

### POST `/api/v1/ingest`

Send a single log line.

**Headers:** `Authorization: Bearer lm_live_4f8a2b9c7d1e6f3a8b5c2d9e7f1a3b6c`

**Request:**
```json
{
  "raw_log": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
  "source": "production-firewall"
}
```

**Response (202 Accepted):**
```json
{
  "status": "accepted",
  "event_id": "evt_f1e2d3c4-b5a6-7890-abcd-ef1234567890"
}
```

---

### POST `/api/v1/ingest/batch`

Send multiple log lines at once.

**Headers:** `Authorization: Bearer lm_live_...`

**Request:**
```json
{
  "logs": [
    "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
    "{\"timestamp\": \"2026-09-23T10:00:00Z\", \"level\": \"ERROR\", \"msg\": \"Connection timeout\"}",
    "CEF:0|Palo Alto|Firewall|9.1|100|TRAFFIC|5|src=192.168.1.10 dst=10.0.0.5 act=ALLOW"
  ],
  "source": "mixed-collector"
}
```

**Response (202 Accepted):**
```json
{
  "status": "accepted",
  "count": 3,
  "event_ids": [
    "evt_aaa11111-...",
    "evt_bbb22222-...",
    "evt_ccc33333-..."
  ]
}
```

---

## 4. Sandbox / Live Demo

This is the **most interactive feature** in the dashboard. The user pastes
any raw log line, clicks "Parse", and instantly sees the normalized output.

### POST `/api/v1/process/sandbox`

Parse a raw log without saving it to the database.

**Headers:** `Authorization: Bearer <jwt_token>`

**Request:**
```json
{
  "raw_log": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
}
```

**Response (200 OK):**
```json
{
  "detected_format": "SYSLOG",
  "parsed_by": "RULE",
  "event": {
    "event_id": "tmp_...",
    "timestamp": "2026-10-11T22:14:15Z",
    "raw_log": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed ...",
    "detected_format": "SYSLOG",
    "severity": "CRITICAL",
    "source": {
      "ip": null,
      "hostname": "mymachine"
    },
    "destination": null,
    "security": {
      "user": "lonvick",
      "process_name": "su"
    },
    "action": "LOGIN_FAILED",
    "parsed_by": "RULE",
    "attributes": {
      "facility": "auth",
      "priority": 34,
      "message": "'su root' failed for lonvick on /dev/pts/8"
    },
    "enrichment": {
      "geoip": null,
      "threat_match": false,
      "mitre_technique": "T1110 - Brute Force"
    }
  }
}
```

> 💡 **Frontend Tip:** This is where you show a beautiful side-by-side view:
> raw log on the left, parsed JSON tree on the right, with format and severity
> badges highlighted.

---

## 5. Log Events & Search

### GET `/api/v1/events`

Get processed events for the current user (paginated).

**Headers:** `Authorization: Bearer <jwt_token>`

**Query Parameters:**
| Param | Type | Default | Example | Description |
| :--- | :--- | :--- | :--- | :--- |
| `page` | int | 1 | `?page=2` | Page number |
| `limit` | int | 25 | `?limit=50` | Events per page (max 100) |
| `severity` | string | — | `?severity=CRITICAL` | Filter by severity level |
| `format` | string | — | `?format=SYSLOG` | Filter by detected format |
| `source` | string | — | `?source=firewall` | Filter by source name |
| `from` | datetime | — | `?from=2026-09-20T00:00:00Z` | Start of time range |
| `to` | datetime | — | `?to=2026-09-23T23:59:59Z` | End of time range |

**Response (200 OK):**
```json
{
  "events": [
    {
      "event_id": "evt_f1e2d3c4-...",
      "timestamp": "2026-09-23T18:30:00Z",
      "raw_log": "<34>Oct 11 22:14:15 mymachine su: ...",
      "detected_format": "SYSLOG",
      "severity": "CRITICAL",
      "source": { "hostname": "mymachine" },
      "action": "LOGIN_FAILED",
      "parsed_by": "RULE",
      "enrichment": {
        "mitre_technique": "T1110"
      }
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 25,
    "total": 142,
    "total_pages": 6
  }
}
```

---

### GET `/api/v1/events/{event_id}`

Get full detail of a single event.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "event_id": "evt_f1e2d3c4-...",
  "timestamp": "2026-09-23T18:30:00Z",
  "raw_log": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
  "detected_format": "SYSLOG",
  "severity": "CRITICAL",
  "source": {
    "ip": "192.168.1.50",
    "hostname": "mymachine",
    "port": null,
    "mac": null
  },
  "destination": null,
  "security": {
    "user": "lonvick",
    "process_name": "su",
    "process_id": null,
    "threat_id": null,
    "mitre_technique": "T1110"
  },
  "action": "LOGIN_FAILED",
  "parsed_by": "RULE",
  "attributes": {
    "facility": "auth",
    "priority": 34,
    "message": "'su root' failed for lonvick on /dev/pts/8"
  },
  "enrichment": {
    "geoip": {
      "country": "India",
      "country_code": "IN",
      "city": "Mumbai",
      "latitude": 19.076,
      "longitude": 72.8777
    },
    "threat_match": false,
    "mitre_technique": "T1110 - Brute Force",
    "mitre_tactic": "Credential Access"
  }
}
```

---

### GET `/api/v1/events/search`

Full-text search across all of the user's log events.

**Headers:** `Authorization: Bearer <jwt_token>`

**Query Parameters:**
| Param | Type | Example | Description |
| :--- | :--- | :--- | :--- |
| `q` | string | `?q=failed login root` | Search query |
| `limit` | int | `?limit=20` | Max results |

**Response (200 OK):**
```json
{
  "query": "failed login root",
  "results": [
    {
      "event_id": "evt_f1e2d3c4-...",
      "timestamp": "2026-09-23T18:30:00Z",
      "severity": "CRITICAL",
      "raw_log": "... 'su root' failed ...",
      "detected_format": "SYSLOG",
      "score": 0.95
    }
  ],
  "total": 3
}
```

---

### DELETE `/api/v1/events/{event_id}`

Delete a specific event.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "message": "Event deleted successfully",
  "event_id": "evt_f1e2d3c4-..."
}
```

---

## 6. Analytics & Stats

All stats endpoints return data scoped to the current user's tenant.

### GET `/api/v1/stats/overview`

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "total_events": 14523,
  "events_today": 342,
  "duplicates_dropped": 891,
  "errors": 23,
  "active_sources": 4,
  "avg_processing_ms": 12.5
}
```

> 💡 **Frontend:** Display these as **6 StatsCard components** in a grid at the
> top of the dashboard.

---

### GET `/api/v1/stats/timeline`

Events over time — for a line/area chart.

**Headers:** `Authorization: Bearer <jwt_token>`

**Query Parameters:**
| Param | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `period` | string | `24h` | Time window: `1h`, `24h`, `7d`, `30d` |
| `bucket` | string | `hour` | Grouping: `minute`, `hour`, `day` |

**Response (200 OK):**
```json
{
  "period": "24h",
  "bucket": "hour",
  "data": [
    { "time": "2026-09-23T00:00:00Z", "count": 45 },
    { "time": "2026-09-23T01:00:00Z", "count": 32 },
    { "time": "2026-09-23T02:00:00Z", "count": 67 },
    { "time": "2026-09-23T03:00:00Z", "count": 12 }
  ]
}
```

> 💡 **Frontend:** Render this as a **line chart** or **area chart** using Recharts.

---

### GET `/api/v1/stats/formats`

Format detection breakdown — for a pie/donut chart.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "formats": [
    { "format": "SYSLOG", "count": 5200, "percentage": 35.8 },
    { "format": "JSON", "count": 4100, "percentage": 28.2 },
    { "format": "CEF", "count": 2800, "percentage": 19.3 },
    { "format": "LEEF", "count": 1200, "percentage": 8.3 },
    { "format": "CLF", "count": 800, "percentage": 5.5 },
    { "format": "UNSTRUCTURED", "count": 423, "percentage": 2.9 }
  ]
}
```

> 💡 **Frontend:** Render this as a **donut chart** with colored segments.

---

### GET `/api/v1/stats/severity`

Severity distribution — for a bar chart.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "severity": [
    { "level": "EMERGENCY", "count": 2, "color": "#DC2626" },
    { "level": "ALERT", "count": 5, "color": "#EA580C" },
    { "level": "CRITICAL", "count": 18, "color": "#E11D48" },
    { "level": "ERROR", "count": 156, "color": "#F59E0B" },
    { "level": "WARNING", "count": 432, "color": "#EAB308" },
    { "level": "NOTICE", "count": 1200, "color": "#3B82F6" },
    { "level": "INFORMATIONAL", "count": 8900, "color": "#22C55E" },
    { "level": "DEBUG", "count": 3810, "color": "#6B7280" }
  ]
}
```

> 💡 **Frontend:** Render this as a **horizontal bar chart**. Use the `color`
> field for each bar.

---

### GET `/api/v1/stats/threats`

Threat intelligence match summary.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "total_threats_detected": 47,
  "threats_today": 3,
  "top_techniques": [
    { "technique": "T1110 - Brute Force", "count": 23 },
    { "technique": "T1059.001 - PowerShell", "count": 12 },
    { "technique": "T1046 - Network Discovery", "count": 8 },
    { "technique": "T1548 - Privilege Escalation", "count": 4 }
  ],
  "recent_iocs": [
    { "type": "ip", "value": "185.220.101.45", "seen_at": "2026-09-23T17:00:00Z" },
    { "type": "domain", "value": "malware-c2.evil.com", "seen_at": "2026-09-23T15:30:00Z" }
  ]
}
```

---

### GET `/api/v1/stats/cascade`

Parsing tier usage — shows how many logs each parsing tier handled.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "tiers": [
    { "tier": "RULE", "label": "Tier 1 — Rule/Regex", "count": 10200, "percentage": 70.2 },
    { "tier": "TEMPLATE", "label": "Tier 2 — Drain3 Templates", "count": 2900, "percentage": 20.0 },
    { "tier": "LLM", "label": "Tier 3 — AI (NVIDIA NIM)", "count": 1100, "percentage": 7.6 },
    { "tier": "FALLBACK", "label": "Fallback — Unparsed", "count": 323, "percentage": 2.2 }
  ]
}
```

> 💡 **Frontend:** Render this as a **stacked bar** or **progress bars**.

---

## 7. Log Sources

### POST `/api/v1/sources`

Register a new log source.

**Headers:** `Authorization: Bearer <jwt_token>`

**Request:**
```json
{
  "name": "Production Firewall",
  "description": "Palo Alto PA-3260 main office",
  "type": "firewall"
}
```

**Response (201 Created):**
```json
{
  "id": "src_p1q2r3",
  "name": "Production Firewall",
  "description": "Palo Alto PA-3260 main office",
  "type": "firewall",
  "created_at": "2026-09-23T10:00:00Z",
  "event_count": 0
}
```

---

### GET `/api/v1/sources`

List all sources.

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "sources": [
    {
      "id": "src_p1q2r3",
      "name": "Production Firewall",
      "description": "Palo Alto PA-3260 main office",
      "type": "firewall",
      "created_at": "2026-09-23T10:00:00Z",
      "event_count": 4523,
      "last_event_at": "2026-09-23T18:45:00Z"
    },
    {
      "id": "src_s4t5u6",
      "name": "AWS CloudTrail",
      "description": "us-east-1 audit logs",
      "type": "cloud",
      "created_at": "2026-09-22T08:00:00Z",
      "event_count": 10000,
      "last_event_at": "2026-09-23T19:00:00Z"
    }
  ]
}
```

---

### DELETE `/api/v1/sources/{source_id}`

Remove a source (does NOT delete its events).

**Headers:** `Authorization: Bearer <jwt_token>`

**Response (200 OK):**
```json
{
  "message": "Source removed successfully",
  "id": "src_p1q2r3"
}
```

---

## 8. System Health

### GET `/health`

No authentication required.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "database": "connected",
  "redis": "connected",
  "uptime_seconds": 84321
}
```

---

## Error Response Format

All errors follow this consistent format:

```json
{
  "detail": "Human-readable error message",
  "error_code": "INVALID_CREDENTIALS",
  "status_code": 401
}
```

Common status codes:
| Code | Meaning |
| :--- | :--- |
| 400 | Bad request (malformed JSON, missing fields) |
| 401 | Unauthorized (expired/invalid JWT or API key) |
| 404 | Resource not found |
| 409 | Conflict (duplicate email, etc.) |
| 422 | Validation error |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
