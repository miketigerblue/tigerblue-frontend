# TigerBlue Frontend (Next.js)

A minimal, production-friendly **Next.js App Router** frontend for TigerBlue / Threat Kitty.

Primary screens:
- `/now` — “what’s happening now” (latest analysis entries + campaign rollups)
- `/timeline` — **7‑Day Pulse** (Signals timeline + Full NVD timeline)
- `/item/[analysisId]` — signal detail
- `/cve/[cveId]` — CVE detail (full record when available)

This frontend is intentionally “API-thin”: it talks directly to **PostgREST**, which exposes **only the `api` schema**.

---

## Requirements

- Node.js 20+
- npm

---

## Setup

```bash
cp .env.example .env.local
npm install
npm run dev
```

Then open:
- http://localhost:3000/now
- http://localhost:3000/timeline

---

## Environment variables

### Required

- `NEXT_PUBLIC_POSTGREST_BASE`
  - Example: `https://your-postgrest.example.com`
  - Must include scheme.

### Optional

- `POSTGREST_AUTH_TOKEN`
  - Bearer token for PostgREST if it is protected.

Notes:
- Client components use `process.env.NEXT_PUBLIC_POSTGREST_BASE` directly for hover/drawer fetches.
- Server components use `lib/postgrest.ts` (`pgGet`) which supports Next fetch caching (`revalidate` + `tags`).

---

## Key PostgREST endpoints used

### Core “signals” endpoints

- `GET /analysis_entries_lite`
  - Cards for `/now` and Signals on `/timeline`
  - Includes `cve_count` which is used for the Signals CVE plot
- `GET /analysis_entries`
  - Enrichment drawer on `/timeline` (structured JSON fields)
- `GET /analysis_entries_campaign`
- `GET /campaign_latest_seen`
- `GET /campaign_cve_rollups`

### CVE endpoints

- `GET /nvd_cves_lite`
  - **Full NVD firehose** “lite” view used by `/timeline` NVD tab.
  - Created to avoid staleness caused by mentions/materialized view dependencies.
- `GET /nvd_cves`
  - Full NVD record used for hover inspection (client-side) and `/cve/[cveId]` (server-side).
- Fallback (optional): `GET /analysis_cves_enriched`
  - Mentions-scoped view used when `/nvd_cves` is not available.

Important staleness note:
- Some `analysis_*` views depend on materialized views of CVE mentions; if those MVs aren’t refreshed, the frontend can look empty even when data exists elsewhere.

---

## `/timeline` behavior (7‑Day Pulse)

### Why the timeline previously showed 0 events

The UI originally used a simple “today + last 7 days” window. When ingestion or materialized views were stale, that window could contain no rows even though the DB had data — just not *recent* data.

### Current solution

Signals on `/timeline` support two windows:

- **Now**: last 7 UTC calendar days anchored on wall-clock time
- **Latest data**: last 7 UTC calendar days anchored on the most recent `analysis_entries_lite.analysed_at`

If data is behind by >24h, the UI shows a banner and suggests switching to **Latest data**.

### Plots

The plot at the top is a stacked “pill-bar” plot by day:

- **Signals tab**: aggregates `analysis_entries_lite.cve_count` per `analysed_at` day (keeps plot consistent with cards + severity filter)
- **NVD tab**: counts CVEs by `nvd_cves_lite.modified` day (full NVD firehose)

---

## Hover / enrichment UX

### Signals

Hovering a signal card opens a right-hand **Enrichment drawer**:

- Fetches `GET /analysis_entries?analysis_id=eq...&select=...&limit=1`
- Displays curated structured fields (recommended actions, IOCs, CVEs, TTPs, etc.)
- Hides empty sections to avoid noisy UI
- Module-level cache to avoid repeat fetches while browsing

### NVD

Hovering an NVD CVE card shows a floating **key-fields inspector** tooltip:

- Debounced fetch to `GET /nvd_cves?cve_id=eq...&select=cve_id,cvss_base,epss,modified,json&limit=1`
- Cached in-memory per session
- Extracts key fields from the full NVD JSON for display (English description, CWEs, vendor/product pairs)
- Includes a link to `/cve/[cveId]` (“View full record →”)

---

## Known issues / next steps

### 1) Plot bars/glow overlapping the day numbers

There is an unresolved UI bug where the plot’s bar/glow (“ball”) visually overlaps the numeric day labels under the plot.

Likely fix:
- Increase separation between the bar area and label row (more vertical space + bottom padding), and/or reduce bar height/glow.

Relevant code:
- `app/timeline/timeline-client.tsx` — the plot block with `gridTemplateRows` and the 44px bar height.

### 2) Tiger icon

A tiger icon integration was discussed but not implemented (asset not committed). Add the image to `public/` and reference via `next/image` or `<img />`.

---

## Development scripts

```bash
npm run dev     # Next dev server
npm run build   # production build
npm run start   # run built app
npm run lint
```

---

## Deployment

This repo is deployable to:
- Vercel
- Fly.io
- Any Docker runtime

### Vercel

- Set env var: `NEXT_PUBLIC_POSTGREST_BASE`
- Optional: `POSTGREST_AUTH_TOKEN`

---

## Key source files (handoff)

- `lib/postgrest.ts` — server-only PostgREST fetch wrapper
- `lib/queries.ts` — timeline + CVE query helpers
- `app/timeline/page.tsx` — server page: computes windows, loads Signals + NVD
- `app/timeline/timeline-client.tsx` — client UI: tabs/toggles/plots/tooltips
- `app/timeline/signal-detail-drawer.tsx` — Signals enrichment drawer (client)
- `app/cve/[cveId]/page.tsx` — CVE page (uses `getCveDetail`)
