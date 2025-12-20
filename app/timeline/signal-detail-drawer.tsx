"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

// Module-level cache so it survives unmount/remount of the drawer.
const analysisDetailCache = new Map<string, AnalysisDetail>();

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

type AnalysisDetail = {
  analysis_id: string;
  analysed_at: string;
  published?: string | null;
  title: string;
  link?: string | null;
  source_name: string;
  severity_level?: string | null;
  confidence_pct?: number | null;
  summary_impact?: string | null;
  recommended_actions?: JsonValue;
  key_iocs?: JsonValue;
  cve_references?: JsonValue;
  ttps?: JsonValue;
  attack_vectors?: JsonValue;
  tools_used?: JsonValue;
  malware_families?: JsonValue;
  exploit_references?: JsonValue;
};

type FetchState =
  | { status: "idle" }
  | { status: "loading"; analysisId: string }
  | { status: "error"; analysisId: string; message: string }
  | { status: "ready"; analysisId: string; data: AnalysisDetail };

function toArray(v: JsonValue | undefined): JsonValue[] {
  if (!v) return [];
  if (Array.isArray(v)) return v;
  return [v];
}

function pretty(v: JsonValue) {
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

function chips(values: JsonValue[], max = 24) {
  const trimmed = values.slice(0, max);
  const rest = Math.max(0, values.length - trimmed.length);
  return { trimmed, rest };
}

function sevColor(sev?: string | null) {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return { fg: "#ff3b6b", bg: "rgba(255,59,107,0.10)", bd: "rgba(255,59,107,0.35)" };
    case "HIGH":
      return { fg: "#ff7a3b", bg: "rgba(255,122,59,0.10)", bd: "rgba(255,122,59,0.35)" };
    case "MEDIUM":
      return { fg: "#ffd43b", bg: "rgba(255,212,59,0.10)", bd: "rgba(255,212,59,0.32)" };
    case "LOW":
      return { fg: "#4dd4ff", bg: "rgba(77,212,255,0.10)", bd: "rgba(77,212,255,0.32)" };
    default:
      return { fg: "rgba(230,236,255,0.8)", bg: "rgba(255,255,255,0.04)", bd: "rgba(255,255,255,0.10)" };
  }
}

function buildUrl(base: string, path: string, params: Record<string, string | number | undefined>) {
  const u = new URL(path, base);
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined) continue;
    u.searchParams.set(k, String(v));
  }
  return u.toString();
}

async function fetchAnalysisDetail(base: string, analysisId: string, signal: AbortSignal) {
  const select = [
    "analysis_id",
    "analysed_at",
    "published",
    "title",
    "link",
    "source_name",
    "severity_level",
    "confidence_pct",
    "summary_impact",
    "recommended_actions",
    "key_iocs",
    "cve_references",
    "ttps",
    "attack_vectors",
    "tools_used",
    "malware_families",
    "exploit_references",
  ].join(",");

  const url = buildUrl(base, "/analysis_entries", {
    analysis_id: `eq.${analysisId}`,
    select,
    limit: 1,
  });

  const res = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`PostgREST ${res.status} ${res.statusText}\n${text}`);
  }

  const rows = (await res.json()) as AnalysisDetail[];
  const row = rows[0];
  if (!row) throw new Error("Not found");
  return row;
}

export default function SignalDetailDrawer({
  analysisId,
  onClose,
}: {
  analysisId: string | null;
  onClose: () => void;
}) {
  const base = process.env.NEXT_PUBLIC_POSTGREST_BASE;

  const [state, setState] = useState<FetchState>({ status: "idle" });

  useEffect(() => {
    if (!analysisId) return;
    if (!base) {
      setState({
        status: "error",
        analysisId,
        message: "Missing NEXT_PUBLIC_POSTGREST_BASE",
      });
      return;
    }

    const cached = analysisDetailCache.get(analysisId);
    if (cached) {
      setState({ status: "ready", analysisId, data: cached });
      return;
    }

    const ac = new AbortController();
    setState({ status: "loading", analysisId });

    fetchAnalysisDetail(base, analysisId, ac.signal)
      .then((data) => {
        analysisDetailCache.set(analysisId, data);
        setState({ status: "ready", analysisId, data });
      })
      .catch((e) => {
        if (ac.signal.aborted) return;
        setState({
          status: "error",
          analysisId,
          message: e instanceof Error ? e.message : String(e),
        });
      });

    return () => ac.abort();
  }, [analysisId, base]);

  const view = useMemo(() => {
    if (!analysisId) return { kind: "empty" as const };
    if (state.status === "ready" && state.analysisId === analysisId) {
      return { kind: "ready" as const, data: state.data };
    }
    if (state.status === "error" && state.analysisId === analysisId) {
      return { kind: "error" as const, message: state.message };
    }
    return { kind: "loading" as const };
  }, [analysisId, state]);

  const drawer = (
    <aside
      className="tb-card"
      style={{
        position: "fixed",
        top: 74,
        right: 16,
        width: 420,
        maxWidth: "calc(100vw - 32px)",
        maxHeight: "calc(100vh - 92px)",
        overflow: "auto",
        padding: 12,
        border: "1px solid rgba(255,255,255,0.12)",
        background:
          "linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02))",
        boxShadow:
          "0 0 26px rgba(0,255,196,0.12), 0 0 44px rgba(255,0,212,0.10)",
        zIndex: 9999,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
        <div style={{ fontWeight: 950, letterSpacing: 0.2, opacity: 0.9 }}>
          Enrichment
        </div>
        <button
          onClick={onClose}
          style={{
            cursor: "pointer",
            borderRadius: 10,
            padding: "4px 10px",
            border: "1px solid rgba(255,255,255,0.16)",
            background: "rgba(255,255,255,0.05)",
            color: "rgba(230,236,255,0.9)",
            fontWeight: 900,
            fontSize: 12,
          }}
        >
          Close
        </button>
      </div>

      {view.kind === "empty" ? (
        <div style={{ marginTop: 12, fontSize: 12, opacity: 0.75 }}>
          Hover a signal card to inspect the enriched fields.
        </div>
      ) : null}

      {view.kind === "loading" ? (
        <div style={{ marginTop: 12, fontSize: 12, opacity: 0.75 }}>
          Loading enrichment…
        </div>
      ) : null}

      {view.kind === "error" ? (
        <div
          style={{
            marginTop: 12,
            padding: 10,
            borderRadius: 14,
            border: "1px solid rgba(255,59,107,0.35)",
            background: "rgba(255,59,107,0.06)",
            fontSize: 12,
            whiteSpace: "pre-wrap",
            opacity: 0.9,
          }}
        >
          {view.message}
        </div>
      ) : null}

      {view.kind === "ready" ? (
        <SignalDetailContent item={view.data} />
      ) : null}
    </aside>
  );

  return drawer;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ marginTop: 12 }}>
      <div style={{ fontSize: 12, opacity: 0.75, fontWeight: 950 }}>{title}</div>
      <div style={{ marginTop: 8 }}>{children}</div>
    </section>
  );
}

function Chip({ label }: { label: string }) {
  return (
    <span
      style={{
        fontSize: 12,
        opacity: 0.9,
        padding: "4px 10px",
        borderRadius: 999,
        border: "1px solid rgba(255,255,255,0.12)",
        background: "rgba(255,255,255,0.03)",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function ChipRow({ values, emptyLabel = "—" }: { values: JsonValue[]; emptyLabel?: string }) {
  if (values.length === 0) return <div style={{ fontSize: 12, opacity: 0.65 }}>{emptyLabel}</div>;

  const { trimmed, rest } = chips(values, 22);
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
      {trimmed.map((v, idx) => (
        <Chip key={idx} label={pretty(v)} />
      ))}
      {rest ? <Chip label={`+${rest} more`} /> : null}
    </div>
  );
}

function KeyValue({ k, v }: { k: string; v: string }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        gap: 10,
        fontSize: 12,
        opacity: 0.85,
      }}
    >
      <div style={{ opacity: 0.7 }}>{k}</div>
      <div style={{ fontWeight: 900, textAlign: "right" }}>{v}</div>
    </div>
  );
}

function SignalDetailContent({ item }: { item: AnalysisDetail }) {
  const sev = sevColor(item.severity_level);

  const cves = toArray(item.cve_references);
  const ttps = toArray(item.ttps);
  const iocs = toArray(item.key_iocs);
  const actions = toArray(item.recommended_actions);
  const attackVectors = toArray(item.attack_vectors);
  const tools = toArray(item.tools_used);
  const malware = toArray(item.malware_families);
  const exploits = toArray(item.exploit_references);

  const summary = (item.summary_impact ?? "").trim();

  const sections = [
    { k: "summary", present: summary.length > 0 },
    { k: "cves", present: cves.length > 0 },
    { k: "ttps", present: ttps.length > 0 },
    { k: "iocs", present: iocs.length > 0 },
    { k: "actions", present: actions.length > 0 },
    { k: "attackVectors", present: attackVectors.length > 0 },
    { k: "tools", present: tools.length > 0 },
    { k: "malware", present: malware.length > 0 },
    { k: "exploits", present: exploits.length > 0 },
  ];

  const presentCount = sections.filter((s) => s.present).length;
  const totalCount = sections.length;

  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ fontWeight: 950, fontSize: 14, lineHeight: 1.2 }}>
        {item.title}
      </div>

      <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <span
          style={{
            fontSize: 12,
            padding: "4px 10px",
            borderRadius: 999,
            border: `1px solid ${sev.bd}`,
            background: sev.bg,
            color: sev.fg,
            fontWeight: 900,
          }}
        >
          {item.severity_level ? item.severity_level.toUpperCase() : "UNKNOWN"}
        </span>
        {typeof item.confidence_pct === "number" ? (
          <Chip label={`confidence ${item.confidence_pct}%`} />
        ) : null}
        <Chip label={item.source_name} />
        <span style={{ fontSize: 12, opacity: 0.65, padding: "4px 2px" }}>
          Coverage: {presentCount}/{totalCount}
        </span>
      </div>

      <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
        <KeyValue k="analysed" v={item.analysed_at.slice(0, 16).replace("T", " ")} />
        {item.published ? (
          <KeyValue k="published" v={item.published.slice(0, 16).replace("T", " ")} />
        ) : null}
        {item.link ? (
          <div style={{ fontSize: 12, opacity: 0.85 }}>
            <a
              href={item.link}
              target="_blank"
              rel="noreferrer"
              style={{ textDecoration: "underline", opacity: 0.9 }}
            >
              source link
            </a>
            <span style={{ opacity: 0.6 }}> · </span>
            <Link href={`/item/${item.analysis_id}`} style={{ textDecoration: "underline" }}>
              open item
            </Link>
          </div>
        ) : (
          <div style={{ fontSize: 12, opacity: 0.85 }}>
            <Link href={`/item/${item.analysis_id}`} style={{ textDecoration: "underline" }}>
              open item
            </Link>
          </div>
        )}
      </div>

      {summary.length > 0 ? (
        <Section title="Summary impact">
          <div
            style={{
              padding: 10,
              borderRadius: 14,
              border: "1px solid rgba(255,255,255,0.10)",
              background: "rgba(255,255,255,0.03)",
              fontSize: 12,
              lineHeight: 1.5,
              opacity: 0.92,
            }}
          >
            {summary}
          </div>
        </Section>
      ) : null}

      {cves.length ? (
        <Section title={`CVEs (${cves.length})`}>
          <ChipRow values={cves} />
        </Section>
      ) : null}

      {ttps.length ? (
        <Section title={`TTPs (${ttps.length})`}>
          <ChipRow values={ttps} />
        </Section>
      ) : null}

      {iocs.length ? (
        <Section title={`Key IOCs (${iocs.length})`}>
          <ChipRow values={iocs} />
        </Section>
      ) : null}

      {actions.length ? (
        <Section title={`Recommended actions (${actions.length})`}>
          <ChipRow values={actions} />
        </Section>
      ) : null}

      {attackVectors.length ? (
        <Section title={`Attack vectors (${attackVectors.length})`}>
          <ChipRow values={attackVectors} />
        </Section>
      ) : null}

      {tools.length ? (
        <Section title={`Tools used (${tools.length})`}>
          <ChipRow values={tools} />
        </Section>
      ) : null}

      {malware.length ? (
        <Section title={`Malware families (${malware.length})`}>
          <ChipRow values={malware} />
        </Section>
      ) : null}

      {exploits.length ? (
        <Section title={`Exploit references (${exploits.length})`}>
          <ChipRow values={exploits} />
        </Section>
      ) : null}
    </div>
  );
}
