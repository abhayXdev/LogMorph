# LogMorph — Frontend Requirements

> This document lists **what the frontend must do** — not how it should look.
> Design decisions (colors, fonts, spacing, animations) are up to the frontend team.

---

## Core Requirements

1. **Dark mode by default.** Light mode is optional for v1.
2. **Fully responsive.** Must work on desktop, tablet, and mobile.
3. **All API calls must include JWT token** in the `Authorization` header after login.
4. **Protected routes** — redirect to `/login` if user is not authenticated.
5. **Loading states** — every API call must show a loading indicator while waiting.
6. **Error handling** — show user-friendly error messages for all API failures.
7. **No page reloads** — single-page app with client-side routing.

---

## Required Pages

| # | Page | Route | Auth? | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Login | `/login` | No | User login with email + password |
| 2 | Signup | `/signup` | No | User registration with name, email, password |
| 3 | Dashboard | `/dashboard` | Yes | Overview stats, charts, recent threats |
| 4 | Log Explorer | `/logs` | Yes | Browse, filter, search all processed logs |
| 5 | Event Detail | `/logs/:eventId` | Yes | Full detail view of a single log event |
| 6 | Sandbox | `/sandbox` | Yes | Paste raw log → see parsed output instantly |
| 7 | API Keys | `/keys` | Yes | Generate, list, and revoke ingestion keys |
| 8 | Sources | `/sources` | Yes | Register and manage log sources |
| 9 | Settings | `/settings` | Yes | User profile and password change |

---

## Required Components

| Component | What it does |
| :--- | :--- |
| **Sidebar Navigation** | Links to all pages, logo at top, logout at bottom, collapsible on mobile |
| **Stats Card** | Shows a metric (number + label), used on the Dashboard |
| **Severity Badge** | Displays severity level (EMERGENCY to DEBUG) with distinct colors |
| **Format Badge** | Displays detected log format (SYSLOG, JSON, CEF, etc.) |
| **Tier Badge** | Shows which parsing tier handled the log (Tier 1, 2, or 3) |
| **Log Table** | Paginated, sortable table of log events |
| **JSON Viewer** | Expandable/collapsible tree view for parsed log JSON |
| **Code Block** | Monospace block for displaying raw log text |
| **Copy Button** | One-click copy to clipboard (used for API keys, code snippets) |

---

## Required Charts (Dashboard Page)

| Chart | Data Source | Type |
| :--- | :--- | :--- |
| Events over time | `GET /api/v1/stats/timeline` | Line or Area chart |
| Format distribution | `GET /api/v1/stats/formats` | Pie or Donut chart |
| Severity distribution | `GET /api/v1/stats/severity` | Bar chart |
| Parsing tier usage | `GET /api/v1/stats/cascade` | Stacked bar or Progress bars |

---

## Required Behaviors

### Authentication Flow
1. User logs in → backend returns JWT token.
2. Store token in `localStorage` or secure cookie.
3. Attach token to every API request: `Authorization: Bearer <token>`.
4. If any API returns `401`, clear token and redirect to `/login`.
5. Token refresh: call `POST /auth/refresh` before expiry.

### API Key Management
1. When a new key is generated, show the **full key only once**.
2. Display a warning: "Save this key now. You won't be able to see it again."
3. Provide a "Copy to Clipboard" button.
4. After creation, the list only shows a masked prefix (e.g., `lm_live_4f8a****`).

### Sandbox Page
1. User pastes any raw log text into a text area.
2. Provide a dropdown with preloaded sample logs (Syslog, JSON, CEF, etc.).
3. User clicks "Parse" → call `POST /api/v1/process/sandbox`.
4. Show the parsed result: detected format, severity, parsing tier, and full JSON output.
5. This is the **demo page** — it should feel interactive and impressive.

### Log Explorer Page
1. Support filtering by: severity, format, source, date range.
2. Support full-text search.
3. Paginate results (25 per page default).
4. Clicking a row navigates to the Event Detail page.

### Event Detail Page
1. Show the original raw log in a code block.
2. Show the full parsed ULS output in an expandable JSON tree.
3. Show enrichment data: GeoIP location, threat intel match, MITRE technique.

---

## API Endpoints to Consume

Refer to [API_CONTRACT.md](API_CONTRACT.md) for the complete list with
request/response JSON examples. Summary:

| Category | Endpoints |
| :--- | :--- |
| Auth | `POST /auth/signup`, `POST /auth/login`, `GET /auth/me`, `POST /auth/refresh` |
| API Keys | `POST /api/v1/keys`, `GET /api/v1/keys`, `DELETE /api/v1/keys/{id}` |
| Sandbox | `POST /api/v1/process/sandbox` |
| Events | `GET /api/v1/events`, `GET /api/v1/events/{id}`, `GET /api/v1/events/search`, `DELETE /api/v1/events/{id}` |
| Stats | `GET /api/v1/stats/overview`, `/timeline`, `/formats`, `/severity`, `/threats`, `/cascade` |
| Sources | `POST /api/v1/sources`, `GET /api/v1/sources`, `DELETE /api/v1/sources/{id}` |
| Health | `GET /health` |
