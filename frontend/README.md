# LogMorph — Web Telemetry Platform & Frontend Dashboard

High-craft enterprise security telemetry and log pre-processing web application for LogMorph. Built with React 19, TypeScript, Vite 6, Tailwind CSS v4, and React Router v7.

Designed with an architectural oxblood and warm bone aesthetic, featuring zero AI-slop layout patterns, accessible interactive components, and sub-millisecond telemetry inspection.

---

## 🚀 Quick Start

### 1. Requirements
* **Node.js**: v20 or later (specified in `.nvmrc`)
* **npm**: v10 or later

### 2. Installation
```bash
# Install dependencies
npm install
```

### 3. Local Development
```bash
# Start local development server on http://localhost:5173
npm run dev
```

During local development, API requests (`/api`, `/auth`, `/health`) are automatically proxied to the live backend at `https://logmorph.onrender.com`.

### 4. Production Build
```bash
# Compile TypeScript and bundle production assets
npm run build

# Preview production build locally
npm run preview
```

Output assets are generated into `dist/` with zero TypeScript errors and zero external runtime dependencies.

---

## ☁️ Cloudflare Pages Deployment

This project is pre-configured for direct, one-click deployment on **Cloudflare Pages**:

1. **SPA Routing**: `public/_redirects` contains `/* /index.html 200` to prevent 404 errors on direct navigation or page refresh.
2. **Security Headers & Caching**: `public/_headers` includes:
   * Anti-clickjacking (`X-Frame-Options: DENY`)
   * MIME-type sniffing defense (`X-Content-Type-Options: nosniff`)
   * Strict CSP allowing connections to `https://logmorph.onrender.com`
   * 1-year immutable caching on `/assets/*`
   * Immediate revalidation on `index.html`
3. **Node Engine**: `.nvmrc` locks the Cloudflare build container to Node 20.

### Cloudflare Pages Build Settings:
* **Framework Preset**: Vite
* **Build Command**: `npm run build`
* **Build Output Directory**: `dist`
* **Node Version**: `20` (or `NODE_VERSION=20` in Environment Variables)

---

## 🎨 Design System & Brand Palette

The user interface follows the authentic LogMorph design token palette:

* **Primary Brand / Oxblood**: `#590907` (Deep Garnet)
* **Base Canvas**: `#faf6f0` (Warm Bone Cream)
* **Surface Container**: `#f6efe5`
* **Header / Sand Accent**: `#e8d2b5`
* **Terminal / Code Block**: `#1a1d15` (Deep Charcoal Olive) with text `#f6efe5`
* **Primary Text**: `#1a1d15`
* **Secondary Text**: `#45483e`
* **Borders & Dividers**: `#c6c8bb`, hover border `#b4b6a9`
* **Severity Badges (RFC 5424)**:
  * **Success / Healthy / Rule**: Text `#0b331e` on `#d8efe0`
  * **Warning / Alert / Amber**: Text `#5a3800` on `#f6dfc2`
  * **Critical / Threat / Crimson**: Text `#7a0008` on `#ffdad5`
  * **Sage / Template**: Text `#34372f` on `#e2e4d6`

---

## 📁 Architecture & File Layout

```
frontend/
├── public/
│   ├── _redirects              # Cloudflare Pages SPA catch-all rule
│   ├── _headers                # Security headers and asset cache directives
│   ├── favicon.png             # LogMorph brand icon
│   └── assets/                 # 96 optimized SVG vectors and Figma primitives
├── src/
│   ├── components/
│   │   ├── AppShell.tsx        # Responsive navigation sidebar, status ping & layout
│   │   ├── JsonTree.tsx        # Expandable ULS syntax tree viewer
│   │   ├── ProtectedRoute.tsx  # JWT authentication gate with fallback spinner
│   │   └── ui.tsx              # Reusable Button, Card, Badge, Modal, Dialog primitives
│   ├── context/
│   │   └── AuthContext.tsx     # Global JWT authentication and session sync
│   ├── lib/
│   │   ├── api.ts              # Resilient API client with 502/503/504 backoff retry
│   │   └── useScrollReveal.ts  # Soft entrance micro-interactions observer
│   ├── pages/
│   │   ├── AppPages.tsx        # Dashboard, Logs, EventDetail, Sandbox, Keys, Sources, Settings
│   │   └── PublicPages.tsx     # Landing, Login, Signup, VerifyEmail, Forgot/ResetPassword, 404
│   ├── App.tsx                 # Client router definitions
│   ├── index.css               # Tailwind CSS v4 directives, font definitions, and easing
│   ├── main.tsx                # React DOM mount point
│   └── vite-env.d.ts           # Vite client environment types
├── docs/                       # Backend API contract and specification documents
├── package.json
├── tsconfig.json
├── vite.config.ts
└── .nvmrc
```

---

## 🤝 Git Contribution Guide

To push this codebase to the repository under your own GitHub account:

```bash
# 1. Initialize git (if starting a new repository) or checkout your feature branch
git checkout -b feat/frontend-telemetry-platform

# 2. Stage all frontend files
git add .

# 3. Commit with your git identity
git commit -m "feat(frontend): implement production telemetry dashboard and Cloudflare deployment"

# 4. Push to remote
git push origin feat/frontend-telemetry-platform
```
