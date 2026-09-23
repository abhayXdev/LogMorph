# LogMorph — Frontend Dashboard

## 👋 Welcome, Frontend Developer!

This directory is your workspace. The backend team is building the Python/FastAPI
API server on the `dev/logmorph` branch. Your job is to build the **React web
dashboard** that connects to that API.

Read the docs in the `docs/` folder carefully before starting:

| Document | What it covers |
| :--- | :--- |
| [API_CONTRACT.md](docs/API_CONTRACT.md) | Every backend endpoint you'll call — with request/response JSON examples |
| [PAGES.md](docs/PAGES.md) | Every page/screen you need to build — with detailed descriptions |
| [DESIGN_SYSTEM.md](docs/DESIGN_SYSTEM.md) | Colors, fonts, spacing, and component guidelines |

---

## Tech Stack (Mandatory)

| Tool | Version | Why |
| :--- | :--- | :--- |
| **React** | 18 or 19 | Component-based UI framework |
| **TypeScript** | 5.x | Type safety — no plain JavaScript |
| **Tailwind CSS** | 3.x or 4.x | Utility-first styling — no custom CSS files |
| **Vite** | 5.x or 6.x | Lightning-fast dev server and bundler |
| **React Router** | 6.x or 7.x | Client-side page navigation |
| **Axios** or **fetch** | — | HTTP calls to the backend API |
| **Lucide React** or **Heroicons** | — | Icon library |
| **Recharts** or **Chart.js** | — | Charts for the analytics dashboard |

---

## Getting Started

```bash
# 1. Navigate to this directory
cd frontend

# 2. Install dependencies
npm install

# 3. Create a .env file (copy from .env.example)
cp .env.example .env

# 4. Start the dev server
npm run dev
```

The dev server should proxy API calls to the backend at `http://localhost:8000`.

Configure this in `vite.config.ts`:
```typescript
export default defineConfig({
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
    }
  }
})
```

---

## Folder Structure (Suggested)

```
frontend/
├── public/
│   └── favicon.svg
├── src/
│   ├── api/                  # API client functions
│   │   ├── auth.ts           # signup(), login(), getMe()
│   │   ├── events.ts         # getEvents(), searchEvents()
│   │   ├── keys.ts           # generateKey(), listKeys(), revokeKey()
│   │   ├── stats.ts          # getOverview(), getTimeline(), getFormats()
│   │   └── client.ts         # Axios instance with JWT interceptor
│   │
│   ├── components/           # Reusable UI components
│   │   ├── Layout.tsx        # Sidebar + topbar shell
│   │   ├── StatsCard.tsx     # Metric card (number + label + icon)
│   │   ├── LogTable.tsx      # Paginated event table
│   │   ├── SeverityBadge.tsx # Color-coded severity pill
│   │   ├── FormatBadge.tsx   # Log format pill (Syslog, CEF, JSON...)
│   │   ├── JsonViewer.tsx    # Expandable JSON tree
│   │   └── ProtectedRoute.tsx# Route guard (redirect to login if no JWT)
│   │
│   ├── pages/                # Full page components (one per route)
│   │   ├── LoginPage.tsx
│   │   ├── SignupPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── LogExplorerPage.tsx
│   │   ├── EventDetailPage.tsx
│   │   ├── SandboxPage.tsx
│   │   ├── ApiKeysPage.tsx
│   │   ├── SourcesPage.tsx
│   │   └── SettingsPage.tsx
│   │
│   ├── hooks/                # Custom React hooks
│   │   ├── useAuth.ts        # Auth state management
│   │   └── useEvents.ts     # Event fetching with pagination
│   │
│   ├── context/              # React Context providers
│   │   └── AuthContext.tsx   # JWT token storage & user state
│   │
│   ├── types/                # TypeScript type definitions
│   │   └── index.ts          # User, Event, ApiKey, Stats interfaces
│   │
│   ├── App.tsx               # Root component with routes
│   ├── main.tsx              # Entry point
│   └── index.css             # Tailwind directives
│
├── docs/                     # Requirements (READ FIRST)
│   ├── API_CONTRACT.md
│   ├── PAGES.md
│   └── DESIGN_SYSTEM.md
│
├── .env.example
├── index.html
├── package.json
├── tailwind.config.js
├── tsconfig.json
└── vite.config.ts
```

---

## Git Rules

- **Branch:** Create your own branch like `feat/frontend-dashboard` from `main`.
- **Commits:** Use conventional commits: `feat(ui): ...`, `fix(ui): ...`, `style(ui): ...`
- **Never commit:** `.env`, `node_modules/`, `dist/`
- **Merge:** Only after the backend team's `dev/logmorph` is merged into `main` and all API endpoints are live.

---

## Questions?

If any API response format is unclear, check `docs/API_CONTRACT.md` first.
If you need a new endpoint or a change, coordinate with the backend team.
