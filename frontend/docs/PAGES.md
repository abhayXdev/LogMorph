# LogMorph — Frontend Pages Specification

> This document describes **every page** the frontend must have.
> Each page includes its route, purpose, what components it contains,
> which API endpoints it calls, and a text-based wireframe description.

---

## Route Map

| Route | Page | Auth Required? |
| :--- | :--- | :--- |
| `/login` | Login Page | No |
| `/signup` | Signup Page | No |
| `/dashboard` | Dashboard (Home) | Yes |
| `/logs` | Log Explorer | Yes |
| `/logs/:eventId` | Event Detail | Yes |
| `/sandbox` | Sandbox / Playground | Yes |
| `/keys` | API Key Management | Yes |
| `/sources` | Log Sources | Yes |
| `/settings` | User Settings | Yes |

> If user is not logged in and visits a protected route, redirect to `/login`.
> If user is logged in and visits `/login` or `/signup`, redirect to `/dashboard`.

---

## Page 1: Login Page (`/login`)

**Purpose:** Allow existing users to log in.

**Layout:**
- Centered card on a dark background.
- LogMorph logo at the top.
- Email input field.
- Password input field (with show/hide toggle).
- "Log In" button.
- Link at the bottom: "Don't have an account? Sign up"

**API Calls:**
- `POST /auth/login` → on success, store JWT token and redirect to `/dashboard`.

**Behavior:**
- Show loading spinner on the button while the API call is in progress.
- Show error message below the form if login fails (e.g., "Invalid email or password").

---

## Page 2: Signup Page (`/signup`)

**Purpose:** Create a new account.

**Layout:**
- Same centered card style as Login.
- Full Name input field.
- Email input field.
- Password input field (with strength indicator: Weak / Medium / Strong).
- Confirm Password field.
- "Create Account" button.
- Link: "Already have an account? Log in"

**API Calls:**
- `POST /auth/signup` → on success, store JWT token and redirect to `/dashboard`.

**Validation (client-side):**
- Email must be valid format.
- Password must be at least 8 characters, include uppercase, lowercase, and a number.
- Confirm password must match.

---

## Page 3: Dashboard (`/dashboard`)

**Purpose:** The main home page after login. Shows an overview of the user's log pipeline.

**Layout (top to bottom):**

### Section A: Stats Cards (top row, 3x2 grid)
Six cards showing key metrics:
1. **Total Events** — big number + small "all time" label
2. **Events Today** — number + green/red arrow showing trend vs yesterday
3. **Duplicates Dropped** — number + "saved" label
4. **Errors** — number in red if > 0
5. **Active Sources** — number + link to `/sources`
6. **Avg Processing Time** — number in milliseconds

**API Call:** `GET /api/v1/stats/overview`

### Section B: Timeline Chart (full width)
A line/area chart showing events over the last 24 hours, grouped by hour.

**API Call:** `GET /api/v1/stats/timeline?period=24h&bucket=hour`

### Section C: Two side-by-side charts

**Left: Format Distribution (Donut Chart)**
Shows what percentage of logs are Syslog vs JSON vs CEF vs others.

**API Call:** `GET /api/v1/stats/formats`

**Right: Severity Distribution (Bar Chart)**
Shows how many logs are CRITICAL, ERROR, WARNING, etc.

**API Call:** `GET /api/v1/stats/severity`

### Section D: Parsing Cascade Breakdown
A horizontal stacked bar or progress bars showing Tier 1 / Tier 2 / Tier 3 usage.

**API Call:** `GET /api/v1/stats/cascade`

### Section E: Recent Threats (small table)
A compact table showing the last 5 threat intelligence matches.

**API Call:** `GET /api/v1/stats/threats`

---

## Page 4: Log Explorer (`/logs`)

**Purpose:** Browse, search, and filter all processed log events.

**Layout:**

### Top Bar: Filters
- **Search box** (full-text search) — calls `GET /api/v1/events/search?q=...`
- **Severity dropdown** — filter by CRITICAL, ERROR, WARNING, etc.
- **Format dropdown** — filter by SYSLOG, JSON, CEF, etc.
- **Date range picker** — from/to date selection
- **Source dropdown** — filter by registered source
- **"Apply Filters" button**

### Main Table
A paginated table with these columns:
| Column | Description |
| :--- | :--- |
| Timestamp | Formatted as `Sep 23, 2026 18:30:00` |
| Severity | Color-coded badge (red for CRITICAL, yellow for WARNING, etc.) |
| Format | Badge showing SYSLOG, JSON, CEF, etc. |
| Source | Hostname or source name |
| Action | What happened (LOGIN_FAILED, ALLOW, BLOCK, etc.) |
| Parsed By | Tier badge (Tier 1, Tier 2, Tier 3) |
| Raw Log | Truncated to first 80 characters with "..." |

**Clicking a row** → navigates to `/logs/:eventId`

### Bottom: Pagination
- "Showing 1-25 of 142 events"
- Previous / Next buttons
- Page number selector

**API Call:** `GET /api/v1/events?page=1&limit=25&severity=...&format=...`

---

## Page 5: Event Detail (`/logs/:eventId`)

**Purpose:** Show the complete detail of a single log event.

**Layout:**

### Header
- Back button ("← Back to Log Explorer")
- Event ID displayed as monospace text
- Severity badge (large)
- Timestamp (human readable + relative: "2 hours ago")

### Two-Column Layout

**Left Column: Raw Log**
- The original raw log line displayed in a dark code block with monospace font.
- Syntax highlighting if possible.

**Right Column: Parsed Output**
- Collapsible JSON tree viewer showing the full `UniversalLogEvent` object.
- Key fields highlighted:
  - Source IP / Hostname
  - Destination IP
  - User
  - Action
  - MITRE Technique (if present)

### Bottom Section: Enrichment Details
Three cards side by side:

1. **GeoIP** — Country flag + country name, city, coordinates on a mini map (optional).
2. **Threat Intel** — "No threats detected" (green) or threat details (red).
3. **MITRE ATT&CK** — Technique ID, name, tactic, and link to MITRE website.

**API Call:** `GET /api/v1/events/{event_id}`

---

## Page 6: Sandbox (`/sandbox`)

**Purpose:** Interactive playground where users can paste any raw log and
see it parsed in real time.

**Layout:**

### Left Side: Input
- Large textarea (at least 6 lines tall) with placeholder text:
  "Paste any raw log here..."
- Dropdown: "Or try a sample" with preloaded examples:
  - Syslog (Linux auth failure)
  - JSON (Kubernetes pod crash)
  - CEF (Firewall ALLOW)
  - LEEF (IBM QRadar)
  - Apache Access Log
  - Messy Unstructured Text
- "Parse Log" button (large, primary color)

### Right Side: Output (appears after parsing)
- **Format Badge** — e.g., "SYSLOG" in blue
- **Parsing Tier Badge** — e.g., "Tier 1 — Rule/Regex" in green
- **Severity Badge** — color coded
- **Parsed JSON Tree** — expandable/collapsible view of the full ULS event
- **Processing Time** — e.g., "Processed in 8ms"

**API Call:** `POST /api/v1/process/sandbox`

> This is the "wow factor" page for demonstrations. Make it look amazing.

---

## Page 7: API Keys (`/keys`)

**Purpose:** Manage ingestion API keys.

**Layout:**

### Top: "Generate New Key" button
Clicking it opens a modal:
- Input: "Key Name" (e.g., "Production Firewall")
- Button: "Generate"
- After generation: Show the full key in a copyable box with a ⚠️ warning:
  "Save this key now. You won't be able to see it again."
- "Copy to Clipboard" button

### Table: Existing Keys
| Column | Description |
| :--- | :--- |
| Name | Key name (e.g., "Production Firewall") |
| Key | Masked prefix (e.g., `lm_live_4f8a****`) |
| Created | Human-readable date |
| Last Used | Date or "Never" |
| Status | Green "Active" badge |
| Actions | Red "Revoke" button |

### Integration Guide (collapsible section below table)
Show code snippets for how to send logs using the API key:

**cURL:**
```bash
curl -X POST https://logmorph-api.onrender.com/api/v1/ingest \
  -H "Authorization: Bearer lm_live_YOUR_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"raw_log": "<34>Oct 11 22:14:15 server sshd: Failed password for root"}'
```

**Python:**
```python
import requests
requests.post(
    "https://logmorph-api.onrender.com/api/v1/ingest",
    headers={"Authorization": "Bearer lm_live_YOUR_KEY_HERE"},
    json={"raw_log": "<34>Oct 11 22:14:15 server sshd: Failed password"}
)
```

**API Calls:**
- `POST /api/v1/keys` (generate)
- `GET /api/v1/keys` (list)
- `DELETE /api/v1/keys/{key_id}` (revoke)

---

## Page 8: Log Sources (`/sources`)

**Purpose:** Register and view log sources sending data to LogMorph.

**Layout:**

### Top: "Add Source" button
Opens a modal with:
- Name input (e.g., "Production Firewall")
- Description textarea
- Type dropdown: Firewall, Server, Cloud, Application, Network, Other
- "Add Source" button

### Table: Sources
| Column | Description |
| :--- | :--- |
| Name | Source name |
| Type | Badge (Firewall, Cloud, etc.) |
| Events | Total event count |
| Last Event | Relative time ("2 min ago") |
| Actions | "Remove" button |

**API Calls:**
- `POST /api/v1/sources`
- `GET /api/v1/sources`
- `DELETE /api/v1/sources/{source_id}`

---

## Page 9: Settings (`/settings`)

**Purpose:** View and update user profile.

**Layout:**
- **Profile Section:** Full name (editable), email (read-only), member since date.
- **Change Password Section:** Current password, new password, confirm new password.
- **Danger Zone:** "Delete Account" button (with confirmation modal).

**API Calls:**
- `GET /auth/me`
- Future: `PUT /auth/me`, `DELETE /auth/me`

---

## Navigation Sidebar

The sidebar should be visible on all pages after login. It should contain:

```
🏠  Dashboard         → /dashboard
📋  Log Explorer      → /logs
🧪  Sandbox           → /sandbox
🔑  API Keys          → /keys
🔌  Sources           → /sources
⚙️   Settings          → /settings
🚪  Logout            → clears JWT, redirects to /login
```

- Active page should be highlighted.
- Sidebar should be collapsible on mobile.
- LogMorph logo at the top of the sidebar.
