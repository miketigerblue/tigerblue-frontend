import Link from "next/link";
import { getKevCves, type KevCveItem } from "@/lib/queries";

function fmtDate(d: string | null) {
  if (!d) return "—";
  return d;
}

function badge(label: string, tone: "good" | "warn" | "bad" | "neutral" = "neutral") {
  const map = {
    good: { bd: "rgba(0,255,196,0.35)", bg: "rgba(0,255,196,0.08)", fg: "rgba(160,255,235,0.95)" },
    warn: { bd: "rgba(255,173,59,0.35)", bg: "rgba(255,173,59,0.08)", fg: "rgba(255,210,160,0.95)" },
    bad: { bd: "rgba(255,59,107,0.35)", bg: "rgba(255,59,107,0.08)", fg: "rgba(255,160,190,0.95)" },
    neutral: { bd: "rgba(255,255,255,0.14)", bg: "rgba(255,255,255,0.05)", fg: "rgba(230,236,255,0.85)" },
  } as const;

  const c = map[tone];
  return (
    <span
      style={{
        fontSize: 12,
        padding: "4px 10px",
        borderRadius: 999,
        border: `1px solid ${c.bd}`,
        background: c.bg,
        color: c.fg,
        fontWeight: 850,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function isOverdue(item: KevCveItem) {
  if (!item.due_date) return false;
  const due = new Date(item.due_date);
  const now = new Date();
  due.setHours(0, 0, 0, 0);
  now.setHours(0, 0, 0, 0);
  return due.getTime() < now.getTime();
}

export default async function KevPage() {
  const kev = await getKevCves(250).catch(() => []);

  const known = kev.filter((k) => (k.known_ransomware_campaign_use ?? "").toLowerCase() === "known");
  const overdue = kev.filter(isOverdue);

  return (
    <main style={{ padding: 20, maxWidth: 1150, margin: "0 auto" }}>
      <header style={{ display: "flex", alignItems: "baseline", gap: 14, flexWrap: "wrap" }}>
        <Link href="/now" style={{ opacity: 0.85 }}>
          ← Now
        </Link>
        <h1 style={{ margin: 0, fontSize: 26, fontWeight: 950, letterSpacing: 0.2 }}>
          KEV
        </h1>
        <div style={{ marginLeft: "auto", fontSize: 12, opacity: 0.75 }}>
          {kev.length} entries (showing latest)
        </div>
      </header>

      <section
        className="tb-card"
        style={{ marginTop: 14, padding: 12, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}
      >
        {badge(`Known ransomware use: ${known.length}`, known.length ? "bad" : "neutral")}
        {badge(`Overdue: ${overdue.length}`, overdue.length ? "warn" : "neutral")}
        <div style={{ marginLeft: "auto", fontSize: 12, opacity: 0.8 }}>
          Source: <b>CISA-KEV</b> (from <code>api.kev_cves_lite</code>)
        </div>
      </section>

      <section style={{ marginTop: 16, display: "grid", gap: 10 }}>
        {kev.map((k) => {
          const ransomware = (k.known_ransomware_campaign_use ?? "Unknown").toString();
          const tone = ransomware.toLowerCase() === "known" ? "bad" : "neutral";

          return (
            <details
              key={k.cve_id}
              className="tb-card"
              style={{ padding: 12, border: overdue.includes(k) ? "1px solid rgba(255,173,59,0.35)" : undefined }}
            >
              <summary style={{ cursor: "pointer", listStyle: "none" }}>
                <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                  <Link href={`/cve/${k.cve_id}`} style={{ fontWeight: 950 }}>
                    {k.cve_id}
                  </Link>
                  <span style={{ fontSize: 12, opacity: 0.75 }}>
                    {k.vendor ?? "—"} · {k.product ?? "—"}
                  </span>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    {badge(ransomware, tone as any)}
                    {isOverdue(k) ? badge("OVERDUE", "warn") : null}
                  </div>
                  <div style={{ marginLeft: "auto", fontSize: 12, opacity: 0.75 }}>
                    added {fmtDate(k.date_added)} · due {fmtDate(k.due_date)}
                  </div>
                </div>

                <div style={{ marginTop: 8, fontWeight: 850, lineHeight: 1.2 }}>
                  {k.vulnerability_name ?? ""}
                </div>

                {k.short_description ? (
                  <div style={{ marginTop: 6, fontSize: 13, opacity: 0.85, lineHeight: 1.45 }}>
                    {k.short_description}
                  </div>
                ) : null}
              </summary>

              {/* expanded details */}
              <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
                {k.required_action ? (
                  <div>
                    <div style={{ fontSize: 12, opacity: 0.7, fontWeight: 900 }}>Required action</div>
                    <div style={{ marginTop: 6, fontSize: 13, opacity: 0.9, lineHeight: 1.5 }}>
                      {k.required_action}
                    </div>
                  </div>
                ) : null}

                {k.notes ? (
                  <div>
                    <div style={{ fontSize: 12, opacity: 0.7, fontWeight: 900 }}>Notes</div>
                    <div style={{ marginTop: 6, fontSize: 13, opacity: 0.9, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
                      {k.notes}
                    </div>
                  </div>
                ) : null}

                <div>
                  <div style={{ fontSize: 12, opacity: 0.7, fontWeight: 900 }}>Full KEV JSON</div>
                  <pre
                    style={{
                      marginTop: 8,
                      fontSize: 12,
                      overflowX: "auto",
                      padding: 12,
                      borderRadius: 14,
                      border: "1px solid rgba(255,255,255,0.10)",
                      background: "rgba(255,255,255,0.03)",
                    }}
                  >
                    {JSON.stringify(k.kev_json, null, 2)}
                  </pre>
                </div>
              </div>
            </details>
          );
        })}

        {kev.length === 0 ? (
          <div className="tb-card" style={{ padding: 12, opacity: 0.8 }}>
            No KEV rows found. Ensure PostgREST exposes <code>api.kev_cves_lite</code>.
          </div>
        ) : null}
      </section>
    </main>
  );
}
