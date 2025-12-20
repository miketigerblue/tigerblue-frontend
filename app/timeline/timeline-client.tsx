"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import type { NvdTimelineItem, TimelineItem } from "@/lib/queries";
import SignalDetailDrawer from "./signal-detail-drawer";

type NvdHoverState = {
  kind: "nvd";
  x: number;
  y: number;
  item: NvdTimelineItem;
};

type NvdCveDetail = {
  cve_id: string;
  cvss_base: number | null;
  epss: number | null;
  modified: string | null;
  json: any;
};

type NvdDetailState =
  | { status: "idle" }
  | { status: "loading"; cveId: string }
  | { status: "error"; cveId: string; message: string }
  | { status: "ready"; cveId: string; data: NvdCveDetail };

type CpePair = { vendor: string; product: string };

type NvdExtract = {
  descriptionEn?: string;
  cwes: string[];
  cpes: CpePair[];
};


function safeToArray(v: any): any[] {
  return Array.isArray(v) ? v : v ? [v] : [];
}

function extractNvd(json: any): NvdExtract {
  const out: NvdExtract = { cwes: [], cpes: [] };

  // NVD 2.0-ish structure: { cve: { descriptions, weaknesses, ... }, configurations: [...] }
  const descriptions = safeToArray(json?.cve?.descriptions);
  const en = descriptions.find((d) => d?.lang === "en" && typeof d?.value === "string");
  if (en?.value) out.descriptionEn = String(en.value);

  const weaknesses = safeToArray(json?.cve?.weaknesses);
  const cweSet = new Set<string>();
  for (const w of weaknesses) {
    for (const d of safeToArray(w?.description)) {
      const val = d?.value;
      if (typeof val === "string" && val.trim()) cweSet.add(val.trim());
    }
  }
  out.cwes = Array.from(cweSet).slice(0, 6);

  const cpeSet = new Set<string>();

  // Common spot: json.configurations[].nodes[].cpeMatch[].criteria
  const configs = safeToArray(json?.configurations);
  const nodes = configs.flatMap((c) => safeToArray(c?.nodes));
  const cpeMatches = nodes.flatMap((n) => safeToArray(n?.cpeMatch));
  const criteria = cpeMatches.map((m) => m?.criteria).filter((c) => typeof c === "string");

  // Also sometimes: json.cve.configurations
  const altConfigs = safeToArray(json?.cve?.configurations);
  const altNodes = altConfigs.flatMap((c) => safeToArray(c?.nodes));
  const altCpeMatches = altNodes.flatMap((n) => safeToArray(n?.cpeMatch));
  const altCriteria = altCpeMatches
    .map((m) => m?.criteria)
    .filter((c) => typeof c === "string");

  for (const c of [...criteria, ...altCriteria]) {
    const parts = String(c).split(":");
    // cpe:2.3:a:vendor:product:version:...
    if (parts.length >= 5 && parts[0] === "cpe" && parts[1] === "2.3") {
      const vendor = parts[3];
      const product = parts[4];
      if (vendor && product) {
        const key = `${vendor}:${product}`;
        if (!cpeSet.has(key)) {
          cpeSet.add(key);
          out.cpes.push({ vendor, product });
          if (out.cpes.length >= 6) break;
        }
      }
    }
  }

  return out;
}

function fmtNum(n: number | null | undefined, digits = 2) {
  if (n == null || !Number.isFinite(n)) return "—";
  return Number(n).toFixed(digits);
}

function dayKey(iso: string) {
  // YYYY-MM-DD
  return iso.slice(0, 10);
}

function sevBucket(sev?: string) {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH" || s === "MEDIUM" || s === "LOW") return s;
  return "NONE";
}

function cvssSevBucket(cvss: number | null) {
  if (cvss === null || !Number.isFinite(cvss)) return "NONE";
  if (cvss >= 9) return "CRITICAL";
  if (cvss >= 7) return "HIGH";
  if (cvss >= 4) return "MEDIUM";
  if (cvss > 0) return "LOW";
  return "NONE";
}


function severityColor(sev?: string) {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return { fg: "#ff3b6b", glow: "rgba(255,59,107,0.55)" };
    case "HIGH":
      return { fg: "#ff7a3b", glow: "rgba(255,122,59,0.45)" };
    case "MEDIUM":
      return { fg: "#ffd43b", glow: "rgba(255,212,59,0.35)" };
    case "LOW":
      return { fg: "#4dd4ff", glow: "rgba(77,212,255,0.35)" };
    default:
      return { fg: "#b7b7ff", glow: "rgba(183,183,255,0.26)" };
  }
}

function clamp01(x: number) {
  return Math.max(0, Math.min(1, x));
}

type TimelineWindow = {
  since: string;
  until: string;
  items: TimelineItem[];
};

type NvdWindow = {
  since: string;
  until: string;
  items: NvdTimelineItem[];
};


type TimelineMode = "now" | "latest";

type StreamMode = "signals" | "nvd";

type DateRange = { from: string; to: string };

function ymdFromIso(iso: string) {
  return iso.slice(0, 10);
}

function isYmd(s: string) {
  return /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function clampRange(from: string, to: string) {
  // Ensure from <= to
  if (!isYmd(from) || !isYmd(to)) return null;
  return from <= to ? { from, to } : { from: to, to: from };
}

function inclusiveDaysYmd(from: string, to: string) {
  const clamped = clampRange(from, to);
  if (!clamped) return 0;
  const a = new Date(`${clamped.from}T00:00:00.000Z`).getTime();
  const b = new Date(`${clamped.to}T00:00:00.000Z`).getTime();
  const diff = Math.floor((b - a) / 86_400_000);
  return Math.max(0, diff) + 1;
}

export default function TimelineClient({
  now,
  latest,
  nvd,
  initialRange,
}: {
  now: TimelineWindow;
  latest: TimelineWindow | null;
  nvd: NvdWindow;
  initialRange: DateRange | null;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const [stream, setStream] = useState<StreamMode>("signals");
  const [mode, setMode] = useState<TimelineMode>("now");
  const [sevFilter, setSevFilter] = useState<string>("ALL");

  const defaultRange = useMemo(() => {
    // Derive a reasonable default from the server-provided window.
    return { from: ymdFromIso(now.since), to: ymdFromIso(now.until) };
  }, [now.since, now.until]);

  const [range, setRange] = useState<DateRange>(() => initialRange ?? defaultRange);

  // Keep the date inputs in sync with the URL (back/forward navigation).
  const urlRange = useMemo(() => {
    const from = searchParams?.get("from") ?? "";
    const to = searchParams?.get("to") ?? "";
    return clampRange(from, to);
  }, [searchParams]);

  useEffect(() => {
    setRange(urlRange ?? defaultRange);
  }, [urlRange?.from, urlRange?.to, defaultRange.from, defaultRange.to]);

  const applyRangeToUrl = (next: DateRange) => {
    const clamped = clampRange(next.from, next.to);
    if (!clamped) return;

    const sp = new URLSearchParams(searchParams?.toString());
    sp.set("from", clamped.from);
    sp.set("to", clamped.to);
    router.push(`${pathname}?${sp.toString()}`);
  };

  const clearRangeFromUrl = () => {
    const sp = new URLSearchParams(searchParams?.toString());
    sp.delete("from");
    sp.delete("to");
    const q = sp.toString();
    router.push(q ? `${pathname}?${q}` : pathname);
  };

  // NVD: small floating hover tooltip + debounced detail fetch.
  const [hover, setHover] = useState<NvdHoverState | null>(null);
  const [nvdDetail, setNvdDetail] = useState<NvdDetailState>({ status: "idle" });
  const nvdDetailCacheRef = useRef(new Map<string, NvdCveDetail>());
  const nvdHoverTimerRef = useRef<number | null>(null);
  const nvdAbortRef = useRef<AbortController | null>(null);

  const postgrestBase = process.env.NEXT_PUBLIC_POSTGREST_BASE;

  const fetchNvdDetail = async (cveId: string, signal: AbortSignal) => {
    if (!postgrestBase) throw new Error("Missing NEXT_PUBLIC_POSTGREST_BASE");

    const u = new URL("/nvd_cves", postgrestBase);
    u.searchParams.set("cve_id", `eq.${cveId}`);
    u.searchParams.set("select", "cve_id,cvss_base,epss,modified,json");
    u.searchParams.set("limit", "1");

    const res = await fetch(u.toString(), {
      method: "GET",
      headers: { Accept: "application/json" },
      signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`PostgREST ${res.status} ${res.statusText}\n${text}`);
    }

    const rows = (await res.json()) as NvdCveDetail[];
    const row = rows[0];
    if (!row) throw new Error("Not found");
    return row;
  };

  const scheduleNvdDetailFetch = (cveId: string) => {
    if (nvdHoverTimerRef.current) window.clearTimeout(nvdHoverTimerRef.current);

    // Cancel previous request when hover changes
    if (nvdAbortRef.current) nvdAbortRef.current.abort();

    const cached = nvdDetailCacheRef.current.get(cveId);
    if (cached) {
      setNvdDetail({ status: "ready", cveId, data: cached });
      return;
    }

    nvdHoverTimerRef.current = window.setTimeout(() => {
      const ac = new AbortController();
      nvdAbortRef.current = ac;
      setNvdDetail({ status: "loading", cveId });

      fetchNvdDetail(cveId, ac.signal)
        .then((data) => {
          nvdDetailCacheRef.current.set(cveId, data);
          setNvdDetail({ status: "ready", cveId, data });
        })
        .catch((e) => {
          if (ac.signal.aborted) return;
          setNvdDetail({
            status: "error",
            cveId,
            message: e instanceof Error ? e.message : String(e),
          });
        });
    }, 160);
  };

  const activeNvdDetail = useMemo(() => {
    if (!hover) return null;
    if (nvdDetail.status === "ready" && nvdDetail.cveId === hover.item.cve_id) return nvdDetail.data;
    return null;
  }, [hover, nvdDetail]);

  const activeNvdExtract = useMemo(() => {
    if (!activeNvdDetail) return null;
    return extractNvd(activeNvdDetail.json);
  }, [activeNvdDetail]);

  // Signals: enrichment drawer.
  const [hoveredAnalysisId, setHoveredAnalysisId] = useState<string | null>(null);
  const hoverTimerRef = useRef<number | null>(null);

  const activeDrawerAnalysisId = stream === "signals" ? hoveredAnalysisId : null;

  const scheduleHoverDrawer = (analysisId: string) => {
    if (hoverTimerRef.current) {
      window.clearTimeout(hoverTimerRef.current);
    }

    hoverTimerRef.current = window.setTimeout(() => {
      setHoveredAnalysisId(analysisId);
    }, 140);
  };

  // Drawer stays until replaced/closed.

  const active = mode === "latest" && latest ? latest : now;
  const { since, until, items } = active;

  const windowSince = stream === "nvd" ? nvd.since : since;
  const windowUntil = stream === "nvd" ? nvd.until : until;

  const filteredSignals = useMemo(() => {
    if (sevFilter === "ALL") return items;
    return items.filter(
      (it) => (it.severity_level ?? "").toUpperCase() === sevFilter
    );
  }, [items, sevFilter]);

  const signalDayGroups = useMemo(() => {
    const m = new Map<string, TimelineItem[]>();
    for (const it of filteredSignals) {
      const k = dayKey(it.analysed_at);
      const arr = m.get(k) ?? [];
      arr.push(it);
      m.set(k, arr);
    }
    const keys = Array.from(m.keys()).sort();
    return keys.map((k) => ({ day: k, items: m.get(k) ?? [] }));
  }, [filteredSignals]);

  const signalMaxPerDay = useMemo(() => {
    return Math.max(1, ...signalDayGroups.map((d) => d.items.length));
  }, [signalDayGroups]);

  const topSources = useMemo(() => {
    // show top 8 sources by total count within the active window
    const totals = new Map<string, number>();
    for (const it of items) {
      const key = it.source_name || "(unknown)";
      totals.set(key, (totals.get(key) ?? 0) + 1);
    }
    return Array.from(totals.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [items]);

  // NVD plot is driven from CVE modified activity (api.nvd_cves_lite.modified).
  // Signals view can also show an analysis-scoped CVE plot (mentions-based).

  function dayKeysBetween(sinceIso: string, untilIso: string) {
    const maxDays = 31;

    const from0 = new Date(sinceIso);
    const to0 = new Date(untilIso);
    from0.setUTCHours(0, 0, 0, 0);
    to0.setUTCHours(0, 0, 0, 0);

    // If the user selects a very large range, keep the plot usable by showing
    // only the most recent 31 days within that selected window.
    const spanDays = Math.floor((to0.getTime() - from0.getTime()) / 86_400_000) + 1;

    const from = spanDays > maxDays ? new Date(to0) : new Date(from0);
    if (spanDays > maxDays) from.setUTCDate(from.getUTCDate() - (maxDays - 1));

    const out: string[] = [];
    for (let d = new Date(from); d.getTime() <= to0.getTime(); d.setUTCDate(d.getUTCDate() + 1)) {
      out.push(d.toISOString().slice(0, 10));
    }
    return out;
  }

  const mentionedPlotDays = useMemo(() => dayKeysBetween(since, until), [since, until]);

  const mentionedCvePlot = useMemo(() => {
    // Plot "CVEs mentioned in signals" based on the signals stream itself.
    // We use `analysis_entries_lite.cve_count` aggregated by analysed_at day.
    // This aligns with what the user sees in the cards for the selected window.

    const buckets = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
    const byDay = new Map<string, Record<(typeof buckets)[number], number>>();

    for (const day of mentionedPlotDays) {
      byDay.set(day, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 });
    }

    for (const it of items) {
      const c = it.cve_count ?? 0;
      if (!c) continue;

      // Keep plot in sync with severity filter (except ALL).
      if (sevFilter !== "ALL") {
        const itSev = (it.severity_level ?? "").toUpperCase();
        if (itSev !== sevFilter) continue;
      }

      const day = dayKey(it.analysed_at);
      const row = byDay.get(day);
      if (!row) continue;

      const b = sevBucket(it.severity_level) as (typeof buckets)[number];
      row[b] += c;
    }

    const data = mentionedPlotDays.map((day) => {
      const row = byDay.get(day) ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
      const total = row.CRITICAL + row.HIGH + row.MEDIUM + row.LOW + row.NONE;
      return { day, ...row, total };
    });

    const maxTotal = Math.max(1, ...data.map((d) => d.total));
    return { buckets, data, maxTotal };
  }, [items, mentionedPlotDays, sevFilter]);

  const nvdDays = useMemo(() => dayKeysBetween(nvd.since, nvd.until), [nvd.since, nvd.until]);

  const nvdByDay = useMemo(() => {
    const m = new Map<string, NvdTimelineItem[]>();
    for (const it of nvd.items) {
      if (!it.modified) continue;
      const k = dayKey(it.modified);
      const arr = m.get(k) ?? [];
      arr.push(it);
      m.set(k, arr);
    }
    return m;
  }, [nvd.items]);

  const nvdDayGroups = useMemo(() => {
    return nvdDays.map((day) => {
      const dayItems = nvdByDay.get(day) ?? [];
      const filteredDayItems =
        sevFilter === "ALL"
          ? dayItems
          : dayItems.filter((it) => cvssSevBucket(it.cvss_base) === sevFilter);
      return { day, items: filteredDayItems };
    });
  }, [nvdDays, nvdByDay, sevFilter]);

  const nvdDaysWithData = useMemo(() => {
    return nvdDayGroups.filter((g) => g.items.length > 0);
  }, [nvdDayGroups]);

  const nvdMaxPerDay = useMemo(() => {
    return Math.max(1, ...nvdDayGroups.map((d) => d.items.length));
  }, [nvdDayGroups]);

  const nvdFilteredCount = useMemo(() => {
    return nvdDayGroups.reduce((acc, d) => acc + d.items.length, 0);
  }, [nvdDayGroups]);

  const nvdCvePlot = useMemo(() => {
    const buckets = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
    const byDay = new Map<string, Record<(typeof buckets)[number], number>>();

    for (const day of nvdDays) {
      byDay.set(day, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 });
    }

    for (const it of nvd.items) {
      if (!it.modified) continue;
      if (sevFilter !== "ALL") {
        if (cvssSevBucket(it.cvss_base) !== sevFilter) continue;
      }
      const day = dayKey(it.modified);
      const row = byDay.get(day);
      if (!row) continue;
      row[cvssSevBucket(it.cvss_base) as (typeof buckets)[number]]++;
    }

    const data = nvdDays.map((day) => {
      const row = byDay.get(day) ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
      const total = row.CRITICAL + row.HIGH + row.MEDIUM + row.LOW + row.NONE;
      return { day, ...row, total };
    });

    const maxTotal = Math.max(1, ...data.map((d) => d.total));
    return { buckets, data, maxTotal };
  }, [nvd.items, nvdDays, sevFilter]);

  const severities =
    stream === "nvd"
      ? (["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const)
      : (["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", ""] as const);

  const staleInfo = useMemo(() => {
    // When a custom range is active, staleness is not meaningful.
    if (initialRange) return null;
    if (!latest) return null;
    const nowD = new Date(now.until);
    const latestD = new Date(latest.until);
    const deltaMs = nowD.getTime() - latestD.getTime();
    if (!Number.isFinite(deltaMs)) return null;

    const hours = Math.floor(deltaMs / 36e5);
    if (hours <= 24) return null;

    const days = Math.floor(hours / 24);
    return { hours, days };
  }, [now.until, latest, initialRange]);

  const activeCount = stream === "nvd" ? nvdFilteredCount : filteredSignals.length;

  return (
    <main
      style={{
        minHeight: "100vh",
        padding: 20,
        background:
          "radial-gradient(900px 600px at 18% 20%, rgba(0, 255, 196, 0.12), transparent 60%), radial-gradient(900px 700px at 75% 25%, rgba(255, 0, 212, 0.10), transparent 55%), radial-gradient(1100px 900px at 50% 85%, rgba(80, 140, 255, 0.10), transparent 60%), #050610",
      }}
    >
      <header style={{ display: "flex", alignItems: "baseline", gap: 14, flexWrap: "wrap" }}>
        <Link href="/now" style={{ opacity: 0.85 }}>
          ← Now
        </Link>
        <h1 style={{ margin: 0, fontSize: 26, fontWeight: 950, letterSpacing: 0.2 }}>
          {inclusiveDaysYmd(ymdFromIso(windowSince), ymdFromIso(windowUntil))}‑Day Pulse
        </h1>

        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            onClick={() => {
              setStream("signals");
              setSevFilter("ALL");
              setHover(null);
            }}
            style={{
              cursor: "pointer",
              borderRadius: 999,
              padding: "4px 10px",
              border:
                stream === "signals"
                  ? "1px solid rgba(0,255,196,0.65)"
                  : "1px solid rgba(255,255,255,0.14)",
              background:
                stream === "signals" ? "rgba(0,255,196,0.10)" : "transparent",
              color: "rgba(230,236,255,0.9)",
              fontWeight: 900,
              fontSize: 12,
            }}
          >
            Signals
          </button>
          <button
            onClick={() => {
              setStream("nvd");
              setMode("now");
              setSevFilter("ALL");
              setHover(null);
              setHoveredAnalysisId(null);
            }}
            style={{
              cursor: "pointer",
              borderRadius: 999,
              padding: "4px 10px",
              border:
                stream === "nvd"
                  ? "1px solid rgba(255,0,212,0.65)"
                  : "1px solid rgba(255,255,255,0.14)",
              background:
                stream === "nvd" ? "rgba(255,0,212,0.10)" : "transparent",
              color: "rgba(230,236,255,0.9)",
              fontWeight: 900,
              fontSize: 12,
            }}
          >
            NVD
          </button>
        </div>

        <div style={{ marginLeft: "auto", display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
          <div style={{ fontSize: 12, opacity: 0.75 }}>
            window {windowSince.slice(0, 10)} → {windowUntil.slice(0, 10)}
          </div>

          {/* Date packer */}
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              type="date"
              value={range.from}
              onChange={(e) => {
                const v = e.target.value;
                if (!isYmd(v)) return;
                const next = { ...range, from: v };
                setRange(next);
                applyRangeToUrl(next);
              }}
              style={{
                fontSize: 12,
                borderRadius: 10,
                border: "1px solid rgba(255,255,255,0.14)",
                background: "rgba(255,255,255,0.04)",
                color: "rgba(230,236,255,0.9)",
                padding: "4px 8px",
              }}
            />
            <span style={{ fontSize: 12, opacity: 0.6 }}>→</span>
            <input
              type="date"
              value={range.to}
              onChange={(e) => {
                const v = e.target.value;
                if (!isYmd(v)) return;
                const next = { ...range, to: v };
                setRange(next);
                applyRangeToUrl(next);
              }}
              style={{
                fontSize: 12,
                borderRadius: 10,
                border: "1px solid rgba(255,255,255,0.14)",
                background: "rgba(255,255,255,0.04)",
                color: "rgba(230,236,255,0.9)",
                padding: "4px 8px",
              }}
            />

            <button
              onClick={() => {
                clearRangeFromUrl();
              }}
              style={{
                cursor: "pointer",
                borderRadius: 999,
                padding: "4px 10px",
                border: "1px solid rgba(255,255,255,0.14)",
                background: "transparent",
                color: "rgba(230,236,255,0.85)",
                fontWeight: 900,
                fontSize: 12,
              }}
              title="Clear custom range"
            >
              Reset
            </button>
          </div>

          {stream === "signals" && latest && !initialRange ? (
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <button
                onClick={() => setMode("now")}
                style={{
                  cursor: "pointer",
                  borderRadius: 999,
                  padding: "4px 10px",
                  border:
                    mode === "now"
                      ? "1px solid rgba(0,255,196,0.65)"
                      : "1px solid rgba(255,255,255,0.14)",
                  background: mode === "now" ? "rgba(0,255,196,0.10)" : "transparent",
                  color: "rgba(230,236,255,0.9)",
                  fontWeight: 900,
                  fontSize: 12,
                }}
              >
                Now
              </button>
              <button
                onClick={() => setMode("latest")}
                style={{
                  cursor: "pointer",
                  borderRadius: 999,
                  padding: "4px 10px",
                  border:
                    mode === "latest"
                      ? "1px solid rgba(255,0,212,0.65)"
                      : "1px solid rgba(255,255,255,0.14)",
                  background:
                    mode === "latest" ? "rgba(255,0,212,0.10)" : "transparent",
                  color: "rgba(230,236,255,0.9)",
                  fontWeight: 900,
                  fontSize: 12,
                }}
              >
                Latest data
              </button>
            </div>
          ) : null}
        </div>

        {stream === "signals" && staleInfo ? (
          <div
            className="tb-card"
            style={{
              width: "100%",
              marginTop: 10,
              padding: 10,
              border: "1px solid rgba(255,173,59,0.35)",
              background: "rgba(255,173,59,0.06)",
              display: "flex",
              gap: 10,
              justifyContent: "space-between",
              alignItems: "baseline",
              flexWrap: "wrap",
            }}
          >
            <div style={{ fontSize: 12, opacity: 0.9, fontWeight: 900 }}>
              Data is behind wall clock by ~{staleInfo.days}d.
            </div>
            <div style={{ fontSize: 12, opacity: 0.8 }}>
              Use <b>Latest data</b> to view the most recent 7‑day window available in the DB.
            </div>
          </div>
        ) : null}
      </header>

      {/* Plot */}
      <section
        className="tb-card"
        style={{
          marginTop: 14,
          padding: 12,
          display: "flex",
          gap: 12,
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <div style={{ fontSize: 12, opacity: 0.75, fontWeight: 900 }}>
          {stream === "signals" ? "CVEs mentioned in signals" : "NVD (modified)"}
        </div>

        {inclusiveDaysYmd(ymdFromIso(windowSince), ymdFromIso(windowUntil)) > 31 ? (
          <div style={{ fontSize: 12, opacity: 0.65 }}>
            Plot shows the most recent 31 days of the selected window.
          </div>
        ) : null}

        <div
          style={{
            display: "grid",
            gridTemplateRows: "62px 14px",
            gap: 6,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "flex-end",
              gap: 8,
              height: 62,
              padding: "6px 8px",
              borderRadius: 14,
              border: "1px solid rgba(255,255,255,0.10)",
              background: "rgba(255,255,255,0.03)",
            }}
          >
            {(stream === "signals" ? mentionedCvePlot : nvdCvePlot).data.map((d) => {
              const maxTotal =
                stream === "signals" ? mentionedCvePlot.maxTotal : nvdCvePlot.maxTotal;
              const scale = 44 / maxTotal;
              const seg = (count: number) => Math.max(0, Math.round(count * scale));
              const cCrit = severityColor("CRITICAL");
              const cHigh = severityColor("HIGH");
              const cMed = severityColor("MEDIUM");
              const cLow = severityColor("LOW");
              const cNone = severityColor(undefined);

              const parts = [
                { k: "CRITICAL", h: seg(d.CRITICAL), col: cCrit.fg, glow: cCrit.glow },
                { k: "HIGH", h: seg(d.HIGH), col: cHigh.fg, glow: cHigh.glow },
                { k: "MEDIUM", h: seg(d.MEDIUM), col: cMed.fg, glow: cMed.glow },
                { k: "LOW", h: seg(d.LOW), col: cLow.fg, glow: cLow.glow },
                { k: "NONE", h: seg(d.NONE), col: cNone.fg, glow: cNone.glow },
              ].filter((p) => p.h > 0);

              const title = `${d.day} • total ${d.total}`;

              return (
                <div
                  key={d.day}
                  title={title}
                  style={{
                    width: 12,
                    height: 44,
                    display: "flex",
                    flexDirection: "column-reverse",
                    justifyContent: "flex-start",
                    borderRadius: 999,
                    overflow: "hidden",
                    background: "rgba(255,255,255,0.06)",
                    boxShadow: d.total
                      ? "0 0 18px rgba(0,255,196,0.12), 0 0 30px rgba(255,0,212,0.10)"
                      : "none",
                  }}
                >
                  {parts.map((p) => (
                    <div
                      key={p.k}
                      style={{
                        height: p.h,
                        background: p.col,
                        boxShadow: `0 0 12px ${p.glow}`,
                      }}
                    />
                  ))}
                </div>
              );
            })}
          </div>

          <div
            style={{
              display: "flex",
              gap: 8,
              paddingLeft: 8,
              fontSize: 10,
              opacity: 0.65,
            }}
          >
            {(stream === "signals" ? mentionedCvePlot : nvdCvePlot).data.map((d) => (
              <div key={d.day} style={{ width: 12, textAlign: "center" }}>
                {d.day.slice(8, 10)}
              </div>
            ))}
          </div>
        </div>

        <div style={{ marginLeft: "auto", fontSize: 12, opacity: 0.75 }}>
          {sevFilter === "ALL" ? "all severities" : `sev=${sevFilter}`}
        </div>
      </section>

      {/* Filter */}
      <section
        className="tb-card"
        style={{
          marginTop: 10,
          padding: 12,
          display: "flex",
          gap: 10,
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <div style={{ fontSize: 12, opacity: 0.75 }}>Filter</div>
        {severities.map((s) => {
          const label = stream === "signals" ? (s === "" ? "UNKNOWN" : s) : s;
          const active = sevFilter === s;
          const col = severityColor(s).fg;
          return (
            <button
              key={label}
              onClick={() => setSevFilter(s)}
              style={{
                appearance: "none",
                cursor: "pointer",
                borderRadius: 999,
                padding: "6px 10px",
                border: active
                  ? `1px solid ${col}`
                  : "1px solid rgba(255,255,255,0.14)",
                background: active ? "rgba(255,255,255,0.06)" : "transparent",
                color: active ? col : "rgba(230,236,255,0.85)",
                boxShadow: active ? `0 0 18px ${severityColor(s).glow}` : "none",
                fontWeight: 800,
                fontSize: 12,
              }}
            >
              {label}
            </button>
          );
        })}

        <div style={{ marginLeft: "auto", fontSize: 12, opacity: 0.75 }}>
          {activeCount} events
        </div>
      </section>

      {/* Timeline */}
      <section
        style={{
          marginTop: 16,
          position: "relative",
          padding: 16,
          borderRadius: 18,
          border: "1px solid rgba(255,255,255,0.10)",
          background:
            "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01))",
          overflow: "hidden",
        }}
        onMouseLeave={() => {
          setHover(null);
          if (nvdHoverTimerRef.current) window.clearTimeout(nvdHoverTimerRef.current);
          if (nvdAbortRef.current) nvdAbortRef.current.abort();
        }}
      >
        {hover ? (
          <div
            className="tb-card"
            style={{
              position: "fixed",
              left: Math.min(window.innerWidth - 380, hover.x + 14),
              top: Math.min(window.innerHeight - 260, hover.y + 14),
              width: 380,
              padding: 12,
              zIndex: 9999,
              pointerEvents: "auto",
              boxShadow:
                "0 0 18px rgba(0,255,196,0.18), 0 0 34px rgba(255,0,212,0.12)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
              <div style={{ fontWeight: 900, lineHeight: 1.15 }}>{hover.item.cve_id}</div>
              <Link
                href={`/cve/${hover.item.cve_id}`}
                style={{
                  fontSize: 12,
                  textDecoration: "underline",
                  opacity: 0.9,
                  whiteSpace: "nowrap",
                }}
              >
                View full record →
              </Link>
            </div>

            <div
              style={{
                marginTop: 8,
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 8,
                fontSize: 12,
                opacity: 0.85,
              }}
            >
              <div>
                <span style={{ opacity: 0.7 }}>Severity</span>
                <div style={{ fontWeight: 900 }}>{cvssSevBucket(hover.item.cvss_base)}</div>
              </div>
              <div>
                <span style={{ opacity: 0.7 }}>Modified</span>
                <div style={{ fontWeight: 900 }}>
                  {hover.item.modified ? hover.item.modified.slice(0, 16).replace("T", " ") : "—"}
                </div>
              </div>
              <div>
                <span style={{ opacity: 0.7 }}>CVSS</span>
                <div style={{ fontWeight: 900 }}>{fmtNum(hover.item.cvss_base, 1)}</div>
              </div>
              <div>
                <span style={{ opacity: 0.7 }}>EPSS</span>
                <div style={{ fontWeight: 900 }}>{fmtNum(hover.item.epss, 3)}</div>
              </div>
            </div>

            {activeNvdExtract?.cwes?.length ? (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 12, opacity: 0.7, fontWeight: 900 }}>CWE</div>
                <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {activeNvdExtract.cwes.map((cwe) => (
                    <span
                      key={cwe}
                      style={{
                        fontSize: 12,
                        padding: "4px 10px",
                        borderRadius: 999,
                        border: "1px solid rgba(255,255,255,0.12)",
                        background: "rgba(255,255,255,0.03)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {cwe}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            {activeNvdExtract?.cpes?.length ? (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 12, opacity: 0.7, fontWeight: 900 }}>Affected</div>
                <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {activeNvdExtract.cpes.map((p) => (
                    <span
                      key={`${p.vendor}:${p.product}`}
                      style={{
                        fontSize: 12,
                        padding: "4px 10px",
                        borderRadius: 999,
                        border: "1px solid rgba(255,255,255,0.12)",
                        background: "rgba(255,255,255,0.03)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {p.vendor} / {p.product}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            <div style={{ marginTop: 10, fontSize: 12, opacity: 0.85, lineHeight: 1.35 }}>
              {activeNvdExtract?.descriptionEn ? (
                <div
                  style={{
                    display: "-webkit-box",
                    WebkitLineClamp: 4,
                    WebkitBoxOrient: "vertical",
                    overflow: "hidden",
                  }}
                >
                  {activeNvdExtract.descriptionEn}
                </div>
              ) : nvdDetail.status === "loading" && nvdDetail.cveId === hover.item.cve_id ? (
                <div style={{ opacity: 0.7 }}>Loading details…</div>
              ) : nvdDetail.status === "error" && nvdDetail.cveId === hover.item.cve_id ? (
                <div style={{ opacity: 0.7 }}>Details unavailable.</div>
              ) : (
                <div
                  style={{
                    display: "-webkit-box",
                    WebkitLineClamp: 4,
                    WebkitBoxOrient: "vertical",
                    overflow: "hidden",
                  }}
                >
                  {hover.item.description_en ?? ""}
                </div>
              )}
            </div>
          </div>
        ) : null}

        {/* neon spine */}
        <div
          style={{
            position: "absolute",
            top: 0,
            bottom: 0,
            left: 34,
            width: 2,
            background:
              "linear-gradient(180deg, rgba(0,255,196,0.0), rgba(0,255,196,0.75), rgba(255,0,212,0.55), rgba(80,140,255,0.65), rgba(0,255,196,0.0))",
            boxShadow:
              "0 0 18px rgba(0,255,196,0.35), 0 0 34px rgba(255,0,212,0.25)",
          }}
        />

        {/* header row */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "92px 1fr",
            gap: 14,
            alignItems: "center",
            paddingBottom: 10,
            borderBottom: "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <div style={{ fontSize: 12, opacity: 0.7 }}>DAY</div>
          <div style={{ fontSize: 12, opacity: 0.7 }}>
            {stream === "nvd" ? "CVEs" : "SIGNALS"}
          </div>
        </div>

        {/* timeline rows */}
        <div style={{ display: "grid", gap: 12, marginTop: 12 }}>
          {stream === "signals" ? (
            <>
              {signalDayGroups.length === 0 ? (
                <div style={{ opacity: 0.75, padding: 12 }}>
                  No events in this window for this filter.
                </div>
              ) : null}

              {signalDayGroups.map((d) => {
                const intensity = clamp01(d.items.length / signalMaxPerDay);
                return (
                  <div
                    key={d.day}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "92px 1fr",
                      gap: 14,
                      alignItems: "start",
                    }}
                  >
                    <div style={{ position: "relative", paddingLeft: 34 }}>
                      <div
                        style={{
                          position: "absolute",
                          left: 16,
                          top: 4,
                          width: 10,
                          height: 10,
                          borderRadius: 999,
                          background: `rgba(0,255,196,${0.25 + 0.55 * intensity})`,
                          boxShadow: `0 0 ${12 + 18 * intensity}px rgba(0,255,196,0.35), 0 0 ${22 + 32 * intensity}px rgba(255,0,212,0.18)`,
                        }}
                      />
                      <div style={{ fontWeight: 900 }}>{d.day.slice(5)}</div>
                      <div style={{ fontSize: 12, opacity: 0.7 }}>{d.items.length} hits</div>
                    </div>

                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
                        gap: 10,
                      }}
                    >
                      {d.items.slice(0, 60).map((it) => {
                        const sev = (it.severity_level ?? "").toUpperCase();
                        const { fg, glow } = severityColor(sev);
                        return (
                          <Link
                            key={it.analysis_id}
                            href={`/item/${it.analysis_id}`}
                            className="tb-card"
                            style={{
                              padding: 10,
                              display: "block",
                              border: `1px solid rgba(255,255,255,0.10)`,
                              transition:
                                "transform 120ms ease, box-shadow 120ms ease, border-color 120ms ease",
                            }}
                            onMouseEnter={() => scheduleHoverDrawer(it.analysis_id)}
                            onMouseLeave={() => {
                              // Keep drawer open after hover; user can close or hover another card.
                              if (hoverTimerRef.current) {
                                window.clearTimeout(hoverTimerRef.current);
                                hoverTimerRef.current = null;
                              }
                            }}
                            onFocus={() => {
                              setHoveredAnalysisId(it.analysis_id);
                            }}
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                              <div
                                style={{
                                  width: 10,
                                  height: 10,
                                  borderRadius: 999,
                                  background: fg,
                                  boxShadow: `0 0 16px ${glow}`,
                                  flex: "0 0 auto",
                                }}
                              />
                              <div style={{ fontWeight: 850, lineHeight: 1.15, flex: "1 1 auto" }}>
                                {it.title}
                              </div>
                            </div>
                            <div style={{ marginTop: 6, fontSize: 12, opacity: 0.75 }}>
                              {it.source_name} · {it.analysed_at.slice(11, 16)} · {sev || "—"}
                            </div>
                            <div
                              style={{
                                marginTop: 8,
                                fontSize: 12,
                                opacity: 0.82,
                                lineHeight: 1.35,
                                display: "-webkit-box",
                                WebkitLineClamp: 3,
                                WebkitBoxOrient: "vertical",
                                overflow: "hidden",
                              }}
                            >
                              {it.summary_impact}
                            </div>
                          </Link>
                        );
                      })}
                      {d.items.length > 60 ? (
                        <div style={{ fontSize: 12, opacity: 0.7, padding: 10 }}>
                          +{d.items.length - 60} more…
                        </div>
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </>
          ) : (
            <>
              {nvdDaysWithData.length === 0 ? (
                <div style={{ opacity: 0.75, padding: 12 }}>
                  No CVEs modified in this window for this filter.
                </div>
              ) : null}

              {nvdDaysWithData.map((d) => {
                const intensity = clamp01(d.items.length / nvdMaxPerDay);
                return (
                  <div
                    key={d.day}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "92px 1fr",
                      gap: 14,
                      alignItems: "start",
                    }}
                  >
                    <div style={{ position: "relative", paddingLeft: 34 }}>
                      <div
                        style={{
                          position: "absolute",
                          left: 16,
                          top: 4,
                          width: 10,
                          height: 10,
                          borderRadius: 999,
                          background: `rgba(255,0,212,${0.20 + 0.55 * intensity})`,
                          boxShadow: `0 0 ${12 + 18 * intensity}px rgba(255,0,212,0.28), 0 0 ${22 + 32 * intensity}px rgba(0,255,196,0.16)`,
                        }}
                      />
                      <div style={{ fontWeight: 900 }}>{d.day.slice(5)}</div>
                      <div style={{ fontSize: 12, opacity: 0.7 }}>{d.items.length} CVEs</div>
                    </div>

                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
                        gap: 10,
                      }}
                    >
                      {d.items.slice(0, 60).map((it) => {
                        const sev = cvssSevBucket(it.cvss_base);
                        const { fg, glow } = severityColor(sev);
                        const time = it.modified ? it.modified.slice(11, 16) : "—";
                        return (
                          <Link
                            key={it.cve_id}
                            href={`/cve/${it.cve_id}`}
                            className="tb-card"
                            style={{
                              padding: 10,
                              display: "block",
                              border: `1px solid rgba(255,255,255,0.10)`,
                              transition:
                                "transform 120ms ease, box-shadow 120ms ease, border-color 120ms ease",
                            }}
                            onMouseEnter={() => scheduleNvdDetailFetch(it.cve_id)}
                            onMouseMove={(e) => {
                              setHover({ kind: "nvd", x: e.clientX, y: e.clientY, item: it });
                            }}
                            onFocus={() => {
                              setHover({ kind: "nvd", x: 24, y: 24, item: it });
                              scheduleNvdDetailFetch(it.cve_id);
                            }}
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                              <div
                                style={{
                                  width: 10,
                                  height: 10,
                                  borderRadius: 999,
                                  background: fg,
                                  boxShadow: `0 0 16px ${glow}`,
                                  flex: "0 0 auto",
                                }}
                              />
                              <div style={{ fontWeight: 900, lineHeight: 1.15 }}>{it.cve_id}</div>
                            </div>
                            <div style={{ marginTop: 6, fontSize: 12, opacity: 0.75 }}>
                              modified · {time} · {sev}
                              {it.cvss_base != null ? ` · CVSS ${it.cvss_base}` : ""}
                              {it.epss != null ? ` · EPSS ${it.epss}` : ""}
                              {Number.isFinite(it.mention_count) ? ` · mentions ${it.mention_count}` : ""}
                            </div>
                            <div
                              style={{
                                marginTop: 8,
                                fontSize: 12,
                                opacity: 0.82,
                                lineHeight: 1.35,
                                display: "-webkit-box",
                                WebkitLineClamp: 3,
                                WebkitBoxOrient: "vertical",
                                overflow: "hidden",
                              }}
                            >
                              {it.description_en ?? ""}
                            </div>
                          </Link>
                        );
                      })}
                      {d.items.length > 60 ? (
                        <div style={{ fontSize: 12, opacity: 0.7, padding: 10 }}>
                          +{d.items.length - 60} more…
                        </div>
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>

        {/* top sources sidebar (signals only) */}
        {stream === "signals" ? (
          <div
            style={{
              marginTop: 16,
              paddingTop: 12,
              borderTop: "1px solid rgba(255,255,255,0.08)",
              display: "flex",
              gap: 14,
              alignItems: "baseline",
              flexWrap: "wrap",
            }}
          >
            <div style={{ fontSize: 12, opacity: 0.7 }}>
              Top sources ({inclusiveDaysYmd(ymdFromIso(windowSince), ymdFromIso(windowUntil))}d)
            </div>
            {topSources.map(([name, cnt]) => (
              <span
                key={name}
                style={{
                  fontSize: 12,
                  opacity: 0.85,
                  padding: "4px 10px",
                  borderRadius: 999,
                  border: "1px solid rgba(255,255,255,0.12)",
                  background: "rgba(255,255,255,0.03)",
                }}
              >
                {name} · {cnt}
              </span>
            ))}
          </div>
        ) : null}
      </section>

      {/* Signals enrichment drawer (hover + pin) */}
      {stream === "signals" && activeDrawerAnalysisId ? (
        <SignalDetailDrawer
          analysisId={activeDrawerAnalysisId}
          onClose={() => {
            setHoveredAnalysisId(null);
          }}
        />
      ) : null}
    </main>
  );
}
