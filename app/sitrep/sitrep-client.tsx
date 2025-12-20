"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { Number2ClusterBrief, Number2DailyInsightsRow, Number2SitrepRow } from "@/lib/types";

type Props = {
  latest: Number2SitrepRow | null;
  history: Number2SitrepRow[];
  insights: Number2DailyInsightsRow | null;
};

function fmtTs(iso?: string | null) {
  if (!iso) return "—";
  return iso.slice(0, 16).replace("T", " ");
}

function bandStyle(band: string) {
  const b = (band ?? "").toLowerCase();
  if (b === "critical") return { fg: "#ff3b6b", bd: "rgba(255,59,107,0.35)", bg: "rgba(255,59,107,0.10)" };
  if (b === "high") return { fg: "#ff7a3b", bd: "rgba(255,122,59,0.35)", bg: "rgba(255,122,59,0.10)" };
  if (b === "medium") return { fg: "#ffd43b", bd: "rgba(255,212,59,0.32)", bg: "rgba(255,212,59,0.10)" };
  return { fg: "rgba(230,236,255,0.85)", bd: "rgba(255,255,255,0.14)", bg: "rgba(255,255,255,0.04)" };
}

function Pill({ children }: { children: React.ReactNode }) {
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
      {children}
    </span>
  );
}

function Metric({ k, v }: { k: string; v: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 10, fontSize: 13, opacity: 0.92 }}>
      <div style={{ opacity: 0.8 }}>{k}</div>
      <div style={{ fontWeight: 900, textAlign: "right" }}>{v}</div>
    </div>
  );
}

function TopWhy({ cluster }: { cluster: Number2ClusterBrief }) {
  const c = cluster.priority_index.components;
  // Pick the “loudest” two components by score.
  const parts = [
    { k: "likelihood", s: c.likelihood.score, why: c.likelihood.why },
    { k: "impact", s: c.impact.score, why: c.impact.why },
    { k: "confidence", s: c.confidence.score, why: c.confidence.why },
    { k: "recency", s: c.recency.score, why: c.recency.why },
    { k: "relevance", s: c.relevance.score, why: c.relevance.why },
  ]
    .sort((a, b) => b.s - a.s)
    .slice(0, 2);

  return (
    <ul style={{ margin: "8px 0 0 0", paddingLeft: 18, fontSize: 13, opacity: 0.9, lineHeight: 1.45 }}>
      {parts.map((p) => (
        <li key={p.k}>{p.why}</li>
      ))}
    </ul>
  );
}

function ClusterDrawer({ cluster, onClose }: { cluster: Number2ClusterBrief | null; onClose: () => void }) {
  if (!cluster) return null;

  const band = bandStyle(cluster.priority_index.band);
  const sources = cluster.source_items ?? [];
  const exploits = sources.flatMap((s) => s.evidence?.exploit_references ?? []).filter(Boolean);

  const cves = (cluster.intelligence?.cves ?? []).map((c) => c.cve_id).slice(0, 10);
  const ttps = (cluster.intelligence?.ttps ?? []).map((t) => t.id || t.name || "").filter(Boolean).slice(0, 12);
  const actions = (cluster.intelligence?.recommended_actions ?? []).slice(0, 12);
  const mitigations = (cluster.intelligence?.mitigations ?? []).slice(0, 12);
  const vectors = (cluster.intelligence?.attack_vectors ?? []).slice(0, 12);

  return (
    <aside
      className="tb-card"
      style={{
        position: "fixed",
        top: 74,
        right: 16,
        width: 460,
        maxWidth: "calc(100vw - 32px)",
        maxHeight: "calc(100vh - 92px)",
        overflow: "auto",
        padding: 12,
        border: "1px solid rgba(255,255,255,0.12)",
        background: "linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02))",
        boxShadow: "0 0 26px rgba(0,255,196,0.12), 0 0 44px rgba(255,0,212,0.10)",
        zIndex: 9999,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
        <div style={{ fontWeight: 950, letterSpacing: 0.2, opacity: 0.95 }}>Sitrep cluster</div>
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

      <div style={{ marginTop: 10, fontWeight: 950, fontSize: 15, lineHeight: 1.25 }}>{cluster.title}</div>

      <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <span
          style={{
            fontSize: 12,
            padding: "4px 10px",
            borderRadius: 999,
            border: `1px solid ${band.bd}`,
            background: band.bg,
            color: band.fg,
            fontWeight: 900,
          }}
        >
          {cluster.priority_index.band.toUpperCase()} · {cluster.priority_index.score}
        </span>
        <Pill>{cluster.cluster_type}</Pill>
        <Pill>
          {cluster.signals_vs_facts.fact_items > 0 ? "facts-backed" : "signal-only"}
        </Pill>
        <Pill>sources {sources.length}</Pill>
      </div>

      <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
        <Metric k="first seen" v={fmtTs(cluster.time.first_seen)} />
        <Metric k="last seen" v={fmtTs(cluster.time.last_seen)} />
        <Metric k="exploit refs" v={String(exploits.length)} />
      </div>

      <section style={{ marginTop: 12 }}>
        <div style={{ fontSize: 13, opacity: 0.85, fontWeight: 950 }}>Why this is ranked</div>
        <TopWhy cluster={cluster} />
      </section>

      {cves.length ? (
        <section style={{ marginTop: 12 }}>
          <div style={{ fontSize: 13, opacity: 0.85, fontWeight: 950 }}>CVEs</div>
          <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
            {cves.map((c) => (
              <Link key={c} href={`/cve/${c}`} style={{ textDecoration: "underline", fontSize: 12, opacity: 0.9 }}>
                {c}
              </Link>
            ))}
          </div>
        </section>
      ) : null}

      {ttps.length ? (
        <section style={{ marginTop: 12 }}>
          <div style={{ fontSize: 13, opacity: 0.85, fontWeight: 950 }}>TTPs</div>
          <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
            {ttps.map((t, idx) => (
              <Pill key={idx}>{t}</Pill>
            ))}
          </div>
        </section>
      ) : null}

      {vectors.length ? (
        <section style={{ marginTop: 12 }}>
          <div style={{ fontSize: 13, opacity: 0.85, fontWeight: 950 }}>Attack vectors</div>
          <ul style={{ margin: "8px 0 0 0", paddingLeft: 18, fontSize: 13, opacity: 0.92, lineHeight: 1.45 }}>
            {vectors.map((v, idx) => (
              <li key={idx}>{v}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {actions.length ? (
        <section style={{ marginTop: 12 }}>
          <div style={{ fontSize: 13, opacity: 0.85, fontWeight: 950 }}>Recommended actions</div>
          <ul style={{ margin: "8px 0 0 0", paddingLeft: 18, fontSize: 13, opacity: 0.92, lineHeight: 1.45 }}>
            {actions.map((a, idx) => (
              <li key={idx}>{a}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {mitigations.length ? (
        <section style={{ marginTop: 12 }}>
          <div style={{ fontSize: 13, opacity: 0.85, fontWeight: 950 }}>Mitigations</div>
          <ul style={{ margin: "8px 0 0 0", paddingLeft: 18, fontSize: 13, opacity: 0.92, lineHeight: 1.45 }}>
            {mitigations.map((m, idx) => (
              <li key={idx}>{m}</li>
            ))}
          </ul>
        </section>
      ) : null}

      <section style={{ marginTop: 12 }}>
        <div style={{ fontSize: 13, opacity: 0.85, fontWeight: 950 }}>Sources</div>
        <div style={{ marginTop: 8, display: "grid", gap: 8 }}>
          {sources.map((s) => {
            const href = s.item_url ?? s.guid;
            const evidence = s.evidence ?? {
              cve_ids: [],
              exploit_references: [],
              ioc_count: 0,
            };

            return (
              <div
                key={s.guid}
                className="tb-card"
                style={{
                  padding: 10,
                  border: "1px solid rgba(255,255,255,0.10)",
                  display: "block",
                  textDecoration: "none",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <div style={{ fontWeight: 900, fontSize: 13, opacity: 0.95 }}>
                    {s.source_name ?? "(unknown source)"}
                  </div>
                  <div style={{ fontSize: 12, opacity: 0.7 }}>{fmtTs(s.analysed_at)}</div>
                </div>

                <div style={{ marginTop: 6, fontSize: 13, opacity: 0.88, wordBreak: "break-word" }}>
                  {href.replace(/^https?:\/\//, "")}
                </div>

                <div style={{ marginTop: 6, fontSize: 13, opacity: 0.85 }}>
                  evidence: {evidence.cve_ids.length} CVE · {evidence.ioc_count} IOC · {evidence.exploit_references.length} refs
                </div>

                <div style={{ marginTop: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
                  <a
                    href={href}
                    target="_blank"
                    rel="noreferrer"
                    style={{ fontSize: 13, opacity: 0.9, textDecoration: "underline" }}
                  >
                    open source ↗
                  </a>

                  {s.analysis_id ? (
                    <Link href={`/item/${s.analysis_id}`} style={{ fontSize: 13, opacity: 0.9, textDecoration: "underline" }}>
                      open item →
                    </Link>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </aside>
  );
}

function InsightsBlock({ insights }: { insights: Number2DailyInsightsRow | null }) {
  if (!insights?.insights) return null;

  const w = insights.insights.window;
  const rt = insights.insights.risk_temperature;

  const topClusters = (insights.insights.top_clusters ?? []).slice(0, 6);
  const topSources = (insights.insights.top_sources ?? []).slice(0, 8);
  const hotCves = (insights.insights.hot_cves ?? []).slice(0, 10);
  const vectors = (insights.insights.attack_vector_themes ?? []).slice(0, 10);

  return (
    <section
      className="tb-card"
      style={{
        padding: 12,
        border: "1px solid rgba(255,255,255,0.12)",
        background:
          "linear-gradient(180deg, rgba(0,255,196,0.08), rgba(255,0,212,0.05) 50%, rgba(255,255,255,0.02))",
        boxShadow: "0 0 26px rgba(0,255,196,0.10), 0 0 44px rgba(255,0,212,0.08)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
        <div style={{ fontWeight: 950, letterSpacing: 0.2, opacity: 0.95 }}>24h Insights</div>
        <div style={{ fontSize: 12, opacity: 0.75 }}>
          window {w?.start?.slice(0, 16).replace("T", " ")} → {w?.end?.slice(0, 16).replace("T", " ")} · sitreps {w?.sitreps ?? "—"}
        </div>
      </div>

      <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <Pill>clusters {rt?.clusters_total ?? "—"}</Pill>
        <Pill>70+ {rt?.clusters_70_plus ?? "—"}</Pill>
        <Pill>50–69 {rt?.clusters_50_69 ?? "—"}</Pill>
        <Pill>under 50 {rt?.clusters_under_50 ?? "—"}</Pill>
      </div>

      <div
        style={{
          marginTop: 12,
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
          gap: 12,
        }}
      >
        {/* Top clusters */}
        <div className="tb-card" style={{ padding: 10, border: "1px solid rgba(255,255,255,0.10)" }}>
          <div style={{ fontSize: 12, opacity: 0.8, fontWeight: 950, textTransform: "uppercase" }}>
            Top clusters
          </div>
          <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
            {topClusters.length ? (
              topClusters.map((c, idx) => (
                <div key={idx} style={{ display: "grid", gap: 4 }}>
                  <div style={{ fontWeight: 900, opacity: 0.95, lineHeight: 1.2 }}>{c.title}</div>
                  <div style={{ fontSize: 12, opacity: 0.75 }}>
                    {c.band ?? "—"} · score {c.score ?? "—"} · items {c.items ?? "—"} · sources {c.sources ?? "—"}
                  </div>
                </div>
              ))
            ) : (
              <div style={{ fontSize: 12, opacity: 0.75 }}>No top clusters.</div>
            )}
          </div>
        </div>

        {/* Hot CVEs */}
        <div className="tb-card" style={{ padding: 10, border: "1px solid rgba(255,255,255,0.10)" }}>
          <div style={{ fontSize: 12, opacity: 0.8, fontWeight: 950, textTransform: "uppercase" }}>
            Hot CVEs
          </div>
          <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
            {hotCves.length ? (
              hotCves.map((c) => (
                <Link
                  key={c.cve_id}
                  href={`/cve/${c.cve_id}`}
                  style={{ textDecoration: "underline", fontSize: 12, opacity: 0.9 }}
                  title={`${c.mentions} mentions · ${c.hours_seen} hours seen`}
                >
                  {c.cve_id}
                </Link>
              ))
            ) : (
              <div style={{ fontSize: 12, opacity: 0.75 }}>No hot CVEs.</div>
            )}
          </div>
        </div>

        {/* Top sources */}
        <div className="tb-card" style={{ padding: 10, border: "1px solid rgba(255,255,255,0.10)" }}>
          <div style={{ fontSize: 12, opacity: 0.8, fontWeight: 950, textTransform: "uppercase" }}>
            Top sources
          </div>
          <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
            {topSources.length ? (
              topSources.map((s, idx) => (
                <div key={idx} style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <div style={{ fontSize: 12, opacity: 0.9 }}>{s.source_name}</div>
                  <div style={{ fontSize: 12, fontWeight: 900, opacity: 0.9, textAlign: "right" }}>
                    {s.items} items · {s.hours_seen}h
                  </div>
                </div>
              ))
            ) : (
              <div style={{ fontSize: 12, opacity: 0.75 }}>No top sources.</div>
            )}
          </div>
        </div>

        {/* Attack vector themes */}
        <div className="tb-card" style={{ padding: 10, border: "1px solid rgba(255,255,255,0.10)" }}>
          <div style={{ fontSize: 12, opacity: 0.8, fontWeight: 950, textTransform: "uppercase" }}>
            Attack vectors
          </div>
          <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
            {vectors.length ? (
              vectors.map((v, idx) => (
                <Pill key={idx}>
                  {v.attack_vector} · {v.mentions} · {v.hours_seen}h
                </Pill>
              ))
            ) : (
              <div style={{ fontSize: 12, opacity: 0.75 }}>No vector themes.</div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export default function SitrepClient({ latest, history, insights }: Props) {
  const [selectedWindowStart, setSelectedWindowStart] = useState<string | null>(latest?.window_start ?? null);
  const [activeClusterId, setActiveClusterId] = useState<string | null>(null);

  const byWindow = useMemo(() => {
    const m = new Map<string, Number2SitrepRow>();
    for (const r of history) m.set(r.window_start, r);
    if (latest) m.set(latest.window_start, latest);
    return m;
  }, [latest, history]);

  const windows = useMemo(() => {
    const rows = Array.from(byWindow.values()).sort((a, b) => (a.window_start < b.window_start ? 1 : -1));
    return rows;
  }, [byWindow]);

  const active = selectedWindowStart ? byWindow.get(selectedWindowStart) ?? null : latest;

  const clusters = active?.report?.ranked_priorities ?? [];

  const activeCluster: Number2ClusterBrief | null = useMemo(() => {
    if (!activeClusterId) return null;
    return clusters.find((c) => c.cluster_id === activeClusterId) ?? null;
  }, [clusters, activeClusterId]);

  const exec = active?.report?.executive_summary;

  return (
    <>
      <InsightsBlock insights={insights} />

      <section
        className="tb-card"
        style={{
          marginTop: insights ? 12 : 0,
          padding: 12,
          display: "flex",
          gap: 12,
          flexWrap: "wrap",
          alignItems: "baseline",
        }}
      >
        <div style={{ fontWeight: 950, opacity: 0.9 }}>Hour</div>
        <select
          value={selectedWindowStart ?? ""}
          onChange={(e) => {
            setSelectedWindowStart(e.target.value);
            setActiveClusterId(null);
          }}
          style={{
            fontSize: 12,
            borderRadius: 10,
            border: "1px solid rgba(255,255,255,0.14)",
            background: "rgba(255,255,255,0.04)",
            color: "rgba(230,236,255,0.9)",
            padding: "6px 10px",
            minWidth: 260,
          }}
        >
          {windows.map((w) => (
            <option key={w.window_start} value={w.window_start}>
              {w.window_start.slice(0, 16).replace("T", " ")} → {w.window_end.slice(11, 16)}
            </option>
          ))}
        </select>

        <div style={{ marginLeft: "auto", fontSize: 13, opacity: 0.85 }}>
          generated {fmtTs(active?.generated_at)} · pipeline {active?.pipeline_version ?? "—"}
        </div>
      </section>

      {exec ? (
        <section className="tb-card" style={{ marginTop: 12, padding: 12 }}>
          <div style={{ fontWeight: 950, fontSize: 15 }}>{exec.headline}</div>
          <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Pill>{exec.numbers.clusters_total} clusters</Pill>
            <Pill>{exec.numbers.cves_mentioned} CVEs</Pill>
            <Pill>{exec.numbers.clusters_priority_high} high/critical</Pill>
            <Pill>{exec.numbers.clusters_priority_medium} medium</Pill>
          </div>
          <ul style={{ margin: "10px 0 0 0", paddingLeft: 18, fontSize: 13, opacity: 0.92, lineHeight: 1.45 }}>
            {(exec.key_points ?? []).slice(0, 5).map((p, idx) => (
              <li key={idx}>{p}</li>
            ))}
          </ul>
        </section>
      ) : null}

      <section
        style={{
          marginTop: 12,
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
          gap: 12,
        }}
      >
        {clusters.length === 0 ? (
          <div className="tb-card" style={{ padding: 12, opacity: 0.8 }}>
            No clusters in this sitrep.
          </div>
        ) : null}

        {clusters.map((c) => {
          const band = bandStyle(c.priority_index.band);
          const sources = c.source_items?.length ?? 0;
          const exploitRefs = (c.source_items ?? []).flatMap((s) => s.evidence?.exploit_references ?? []).length;

          return (
            <button
              key={c.cluster_id}
              onClick={() => setActiveClusterId(c.cluster_id)}
              className="tb-card"
              style={{
                textAlign: "left",
                cursor: "pointer",
                padding: 12,
                border: activeClusterId === c.cluster_id ? `1px solid ${band.fg}` : "1px solid rgba(255,255,255,0.10)",
                background: "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01))",
                boxShadow: activeClusterId === c.cluster_id ? `0 0 20px ${band.bg}` : "none",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "baseline" }}>
                <div style={{ fontWeight: 950, lineHeight: 1.15 }}>{c.title}</div>
                <span
                  style={{
                    fontSize: 12,
                    padding: "4px 10px",
                    borderRadius: 999,
                    border: `1px solid ${band.bd}`,
                    background: band.bg,
                    color: band.fg,
                    fontWeight: 900,
                    whiteSpace: "nowrap",
                  }}
                >
                  {c.priority_index.band.toUpperCase()} · {c.priority_index.score}
                </span>
              </div>

              <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                <Pill>{c.cluster_type}</Pill>
                <Pill>{c.signals_vs_facts.fact_items > 0 ? "facts-backed" : "signal-only"}</Pill>
                <Pill>sources {sources}</Pill>
                <Pill>refs {exploitRefs}</Pill>
              </div>

              <TopWhy cluster={c} />

              <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
                <Metric k="first" v={fmtTs(c.time.first_seen)} />
                <Metric k="last" v={fmtTs(c.time.last_seen)} />
              </div>
            </button>
          );
        })}
      </section>

      <ClusterDrawer cluster={activeCluster} onClose={() => setActiveClusterId(null)} />
    </>
  );
}
