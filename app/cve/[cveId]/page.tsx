import Link from "next/link";
import {
  getCveCampaigns,
  getCveDetail,
  getEpssLatestForCve,
  getKevLiteForCve,
  getNvdLiteForCve,
} from "@/lib/queries";
import { extractNvd } from "@/lib/nvd-extract";

function fmtNum(n: number | null | undefined, digits = 2) {
  if (n == null || !Number.isFinite(n)) return "—";
  return Number(n).toFixed(digits);
}

function fmtIso(iso: string | null | undefined) {
  if (!iso) return "—";
  // YYYY-MM-DD HH:mm
  return iso.slice(0, 16).replace("T", " ");
}

function cvssSev(cvss: number | null | undefined) {
  if (cvss == null || !Number.isFinite(cvss)) return "UNKNOWN" as const;
  if (cvss >= 9) return "CRITICAL" as const;
  if (cvss >= 7) return "HIGH" as const;
  if (cvss >= 4) return "MEDIUM" as const;
  if (cvss > 0) return "LOW" as const;
  return "NONE" as const;
}

function toneForSev(sev: string) {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return { fg: "#ff3b6b", glow: "rgba(255,59,107,0.55)", bd: "rgba(255,59,107,0.35)", bg: "rgba(255,59,107,0.08)" };
    case "HIGH":
      return { fg: "#ff7a3b", glow: "rgba(255,122,59,0.45)", bd: "rgba(255,122,59,0.35)", bg: "rgba(255,122,59,0.08)" };
    case "MEDIUM":
      return { fg: "#ffd43b", glow: "rgba(255,212,59,0.35)", bd: "rgba(255,212,59,0.32)", bg: "rgba(255,212,59,0.08)" };
    case "LOW":
      return { fg: "#4dd4ff", glow: "rgba(77,212,255,0.35)", bd: "rgba(77,212,255,0.32)", bg: "rgba(77,212,255,0.08)" };
    default:
      return { fg: "rgba(230,236,255,0.85)", glow: "rgba(183,183,255,0.26)", bd: "rgba(255,255,255,0.14)", bg: "rgba(255,255,255,0.05)" };
  }
}

function pill(label: string, tone: ReturnType<typeof toneForSev>) {
  return (
    <span
      style={{
        fontSize: 12,
        padding: "6px 12px",
        borderRadius: 999,
        border: `1px solid ${tone.bd}`,
        background: tone.bg,
        color: tone.fg,
        fontWeight: 900,
        whiteSpace: "nowrap",
        boxShadow: `0 0 18px ${tone.glow}`,
      }}
    >
      {label}
    </span>
  );
}

function softPill(label: string) {
  return (
    <span
      style={{
        fontSize: 12,
        padding: "6px 12px",
        borderRadius: 999,
        border: "1px solid rgba(255,255,255,0.14)",
        background: "rgba(255,255,255,0.05)",
        color: "rgba(230,236,255,0.85)",
        fontWeight: 850,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function sectionTitle(title: string, hint?: string) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "baseline", flexWrap: "wrap" }}>
      <div style={{ fontSize: 12, opacity: 0.7, fontWeight: 950, letterSpacing: 0.2, textTransform: "uppercase" }}>
        {title}
      </div>
      {hint ? <div style={{ fontSize: 12, opacity: 0.65 }}>{hint}</div> : null}
    </div>
  );
}

export default async function CvePage({
  params,
}: {
  params: Promise<{ cveId: string }>;
}) {
  const { cveId } = await params;

  const [detailRes, campaignsRes, epssRes, kevRes, nvdLiteRes] = await Promise.allSettled([
    getCveDetail(cveId),
    getCveCampaigns(cveId, 50),
    getEpssLatestForCve(cveId),
    getKevLiteForCve(cveId),
    getNvdLiteForCve(cveId),
  ]);

  const detail = detailRes.status === "fulfilled" ? detailRes.value : null;
  const campaigns = campaignsRes.status === "fulfilled" ? campaignsRes.value : [];
  const epss = epssRes.status === "fulfilled" ? epssRes.value : null;
  const kev = kevRes.status === "fulfilled" ? kevRes.value : null;
  const nvdLite = nvdLiteRes.status === "fulfilled" ? nvdLiteRes.value : null;

  const detailJson = (detail as any)?.json ?? null;
  const nvd = detailJson ? extractNvd(detailJson) : { descriptionEn: undefined, cwes: [], cpes: [], references: [] };

  const cvss = ((detail as any)?.cvss_base as number | null | undefined) ?? nvdLite?.cvss_base;
  const epssInline = ((detail as any)?.epss as number | null | undefined) ?? nvdLite?.epss;
  const modified = ((detail as any)?.modified as string | null | undefined) ?? nvdLite?.modified;

  // When api.cve_detail exists, these will be populated and we can reduce extra calls later.
  const epssPercentile = (detail as any)?.epss_percentile as number | null | undefined;
  const epssAsOf = (detail as any)?.epss_as_of as string | null | undefined;
  const inKev = (detail as any)?.in_kev as boolean | null | undefined;

  const mentionCount = (detail as any)?.mention_count as number | null | undefined;
  const lastSeen = (detail as any)?.last_seen as string | null | undefined;

  const campaignCount = (detail as any)?.campaign_count as number | null | undefined;
  const campaignLastSeen = (detail as any)?.campaign_last_seen as string | null | undefined;

  const sev = cvssSev(cvss);
  const sevTone = toneForSev(sev);

  const headline = ((nvd.descriptionEn ?? "").trim() || (nvdLite?.description_en ?? "").trim());

  const kevTone = (() => {
    const k = (kev?.known_ransomware_campaign_use ?? "").toLowerCase();
    if (k === "known") return toneForSev("CRITICAL");
    if (k) return toneForSev("MEDIUM");
    return toneForSev("UNKNOWN");
  })();

  return (
    <main
      style={{
        minHeight: "100vh",
        padding: 20,
        background:
          "radial-gradient(900px 600px at 18% 20%, rgba(0, 255, 196, 0.10), transparent 60%), radial-gradient(900px 700px at 75% 25%, rgba(255, 0, 212, 0.09), transparent 55%), radial-gradient(1100px 900px at 50% 85%, rgba(80, 140, 255, 0.08), transparent 60%), #050610",
      }}
    >
      <div style={{ maxWidth: 1150, margin: "0 auto" }}>
        <header style={{ display: "flex", alignItems: "baseline", gap: 14, flexWrap: "wrap" }}>
          <Link href="/now" style={{ opacity: 0.85 }}>
            ← Now
          </Link>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 950, letterSpacing: 0.2 }}>
            {cveId}
          </h1>

          <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            {pill(`CVSS ${cvss == null ? "—" : fmtNum(cvss, 1)} · ${sev}`, sevTone)}
            {softPill(`EPSS ${epssInline == null ? "—" : fmtNum(epssInline, 4)}`)}
            {(epss?.percentile ?? epssPercentile) != null ? (
              softPill(
                `percentile ${fmtNum(((epss?.percentile ?? epssPercentile) as number) * 100, 1)}%`
              )
            ) : null}
            {kev || inKev ? (
              pill(
                `KEV ${(kev?.known_ransomware_campaign_use ?? (inKev ? "listed" : "")) || "listed"}`,
                kevTone
              )
            ) : (
              softPill("KEV —")
            )}
          </div>
        </header>

        {/* Hero */}
        <section
          className="tb-card"
          style={{
            marginTop: 14,
            padding: 14,
            border: "1px solid rgba(255,255,255,0.12)",
            background:
              "linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02))",
            boxShadow: `0 0 26px rgba(0,255,196,0.10), 0 0 44px rgba(255,0,212,0.08)`,
          }}
        >
          <div style={{ display: "grid", gap: 10 }}>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
              <div style={{ fontSize: 12, opacity: 0.75 }}>last modified</div>
              <div style={{ fontSize: 12, fontWeight: 900 }}>{fmtIso(modified)}</div>
              {epss?.as_of || epssAsOf ? (
                <div style={{ marginLeft: "auto", fontSize: 12, opacity: 0.75 }}>
                  EPSS as_of {epss?.as_of ?? epssAsOf}
                </div>
              ) : null}
            </div>

            {headline ? (
              <div
                style={{
                  fontSize: 14,
                  lineHeight: 1.55,
                  opacity: 0.92,
                  display: "-webkit-box",
                  WebkitLineClamp: 4,
                  WebkitBoxOrient: "vertical",
                  overflow: "hidden",
                }}
              >
                {headline}
              </div>
            ) : detail ? (
              <div style={{ fontSize: 13, opacity: 0.75 }}>
                No English description found in the JSON payload.
              </div>
            ) : nvdLite ? (
              <div style={{ fontSize: 13, opacity: 0.75 }}>
                Full CVE JSON not available; showing summary from <code>/nvd_cves_lite</code>.
              </div>
            ) : (
              <div style={{ fontSize: 13, opacity: 0.75 }}>
                No CVE record found. (Tried <code>/nvd_cves</code>, <code>/analysis_cves_enriched</code>, and <code>/nvd_cves_lite</code>.)
              </div>
            )}
          </div>
        </section>

        <section style={{ marginTop: 12, display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 12 }}>
          {/* Left column */}
          <div style={{ display: "grid", gap: 12 }}>
            {/* Affected */}
            <section className="tb-card" style={{ padding: 12 }}>
              {sectionTitle("Affected products", nvd.cpes.length ? `${nvd.cpes.length} unique vendor/product pairs` : "" )}
              <div style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 8 }}>
                {nvd.cpes.length ? (
                  nvd.cpes.map((p) => (
                    <span
                      key={`${p.vendor}:${p.product}`}
                      style={{
                        fontSize: 12,
                        padding: "6px 10px",
                        borderRadius: 999,
                        border: "1px solid rgba(255,255,255,0.12)",
                        background: "rgba(255,255,255,0.03)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {p.vendor} / {p.product}
                    </span>
                  ))
                ) : (
                  <div style={{ fontSize: 12, opacity: 0.7 }}>No CPE vendor/product pairs available.</div>
                )}
              </div>
            </section>

            {/* References */}
            <section className="tb-card" style={{ padding: 12 }}>
              {sectionTitle("References", nvd.references.length ? `showing ${Math.min(40, nvd.references.length)}` : "" )}
              <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
                {nvd.references.length ? (
                  nvd.references.slice(0, 30).map((r) => (
                    <a
                      key={r.url}
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr auto",
                        gap: 10,
                        alignItems: "baseline",
                        padding: "10px 10px",
                        borderRadius: 14,
                        border: "1px solid rgba(255,255,255,0.10)",
                        background: "rgba(255,255,255,0.02)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: 12,
                          opacity: 0.88,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={r.url}
                      >
                        {r.url}
                      </div>
                      <div style={{ fontSize: 11, opacity: 0.65, textAlign: "right" }}>
                        {r.source ?? "ref"}
                      </div>
                      {r.tags?.length ? (
                        <div style={{ gridColumn: "1 / -1", display: "flex", gap: 8, flexWrap: "wrap" }}>
                          {r.tags.slice(0, 6).map((t) => (
                            <span
                              key={t}
                              style={{
                                fontSize: 11,
                                opacity: 0.8,
                                padding: "4px 8px",
                                borderRadius: 999,
                                border: "1px solid rgba(255,255,255,0.10)",
                                background: "rgba(255,255,255,0.02)",
                              }}
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </a>
                  ))
                ) : (
                  <div style={{ fontSize: 12, opacity: 0.7 }}>No references available.</div>
                )}
              </div>
            </section>
          </div>

          {/* Right column */}
          <div style={{ display: "grid", gap: 12 }}>
            {/* Weaknesses */}
            <section className="tb-card" style={{ padding: 12 }}>
              {sectionTitle("Weaknesses (CWE)", nvd.cwes.length ? `${nvd.cwes.length}` : "" )}
              <div style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 8 }}>
                {nvd.cwes.length ? (
                  nvd.cwes.map((cwe) => (
                    <span
                      key={cwe}
                      style={{
                        fontSize: 12,
                        padding: "6px 10px",
                        borderRadius: 999,
                        border: "1px solid rgba(255,255,255,0.12)",
                        background: "rgba(255,255,255,0.03)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {cwe}
                    </span>
                  ))
                ) : (
                  <div style={{ fontSize: 12, opacity: 0.7 }}>No CWE labels found.</div>
                )}
              </div>
            </section>

            {/* KEV details */}
            <section className="tb-card" style={{ padding: 12 }}>
              {sectionTitle("KEV", "CISA Known Exploited Vulnerabilities")}
              {kev ? (
                <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
                  <div style={{ fontSize: 12, opacity: 0.85 }}>
                    added <b>{kev.date_added ?? "—"}</b> · due <b>{kev.due_date ?? "—"}</b>
                  </div>
                  {kev.vulnerability_name ? (
                    <div style={{ fontWeight: 900, lineHeight: 1.25 }}>{kev.vulnerability_name}</div>
                  ) : null}
                  {kev.short_description ? (
                    <div style={{ fontSize: 12, opacity: 0.8, lineHeight: 1.5 }}>{kev.short_description}</div>
                  ) : null}
                  {kev.required_action ? (
                    <div style={{ fontSize: 12, opacity: 0.85, lineHeight: 1.5 }}>
                      <span style={{ opacity: 0.7 }}>required action:</span> {kev.required_action}
                    </div>
                  ) : null}
                </div>
              ) : (
                <div style={{ marginTop: 10, fontSize: 12, opacity: 0.7 }}>
                  KEV row not available (either not listed, or PostgREST doesn’t expose <code>api.kev_cves_lite</code>).
                </div>
              )}
            </section>

            {/* Activity */}
            <section className="tb-card" style={{ padding: 12 }}>
              {sectionTitle(
                "Activity",
                `${campaignCount ?? campaigns.length} campaigns · ${mentionCount ?? "—"} mentions · last ${campaignLastSeen ?? lastSeen ?? "—"}`
              )}
              <div style={{ marginTop: 10, display: "grid", gap: 10 }}>
                {campaigns.map((c) => (
                  <div
                    key={c.campaign_key}
                    style={{
                      padding: 10,
                      borderRadius: 14,
                      border: "1px solid rgba(255,255,255,0.10)",
                      background: "rgba(255,255,255,0.02)",
                      display: "grid",
                      gap: 6,
                    }}
                  >
                    <Link href={`/campaign/${encodeURIComponent(c.campaign_key)}`} style={{ fontWeight: 950 }}>
                      {c.campaign_key}
                    </Link>
                    <div style={{ fontSize: 12, opacity: 0.8 }}>
                      items <b>{c.item_count}</b> · mentions <b>{c.mention_count}</b> · last <b>{c.last_seen}</b>
                    </div>
                  </div>
                ))}

                {campaigns.length === 0 ? (
                  <div style={{ fontSize: 12, opacity: 0.7 }}>
                    No campaign rollups found.
                  </div>
                ) : null}
              </div>
            </section>
          </div>
        </section>

        {/* Raw JSON */}
        <section style={{ marginTop: 12 }}>
          {detailJson ? (
            <details className="tb-card" style={{ padding: 12 }}>
              <summary
                style={{
                  cursor: "pointer",
                  listStyle: "none",
                  display: "flex",
                  gap: 10,
                  alignItems: "baseline",
                }}
              >
                <span style={{ fontWeight: 950 }}>Raw CVE JSON</span>
                <span style={{ fontSize: 12, opacity: 0.7 }}>(expand)</span>
              </summary>
              <div style={{ marginTop: 12 }} className="tb-prose">
                <pre style={{ margin: 0 }}>{JSON.stringify(detailJson, null, 2)}</pre>
              </div>
            </details>
          ) : (
            <div className="tb-card" style={{ padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                <div style={{ fontWeight: 950 }}>Raw CVE JSON</div>
                <div style={{ fontSize: 12, opacity: 0.65 }}>unavailable</div>
              </div>
              <div style={{ marginTop: 8, fontSize: 12, opacity: 0.75, lineHeight: 1.6 }}>
                This CVE page is currently rendering from a summary endpoint (<code>/nvd_cves_lite</code>) or a
                non-NVD enrichment view. To enable raw JSON, expose the one-stop view <code>api.cve_detail</code>
                (or <code>api.nvd_cves</code>) via PostgREST.
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
