import Link from "next/link";
import { getEpssMovers24h, getEpssTopLatest } from "@/lib/queries";

function fmtNum(n: number | null | undefined, digits = 3) {
  if (n == null || !Number.isFinite(n)) return "—";
  return Number(n).toFixed(digits);
}

export default async function EpssPage() {
  const [topRes, moversRes] = await Promise.allSettled([
    getEpssTopLatest(200),
    getEpssMovers24h(200),
  ]);

  const top = topRes.status === "fulfilled" ? topRes.value : [];
  const movers = moversRes.status === "fulfilled" ? moversRes.value : [];

  const topErr =
    topRes.status === "rejected"
      ? topRes.reason instanceof Error
        ? topRes.reason.message
        : String(topRes.reason)
      : null;

  const moversErr =
    moversRes.status === "rejected"
      ? moversRes.reason instanceof Error
        ? moversRes.reason.message
        : String(moversRes.reason)
      : null;

  return (
    <main style={{ padding: 20, maxWidth: 1150, margin: "0 auto" }}>
      <header style={{ display: "flex", alignItems: "baseline", gap: 14, flexWrap: "wrap" }}>
        <Link href="/now" style={{ opacity: 0.85 }}>
          ← Now
        </Link>
        <h1 style={{ margin: 0, fontSize: 26, fontWeight: 950, letterSpacing: 0.2 }}>
          EPSS
        </h1>
        <div style={{ marginLeft: "auto", fontSize: 12, opacity: 0.75 }}>
          Top EPSS + 24h movers
        </div>
      </header>

      <section
        className="tb-card"
        style={{ marginTop: 14, padding: 12, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}
      >
        <div style={{ fontSize: 12, opacity: 0.8 }}>
          <div style={{ fontWeight: 900 }}>Data sources</div>
          <div style={{ marginTop: 4 }}>
            <code>api.epss_top_latest</code> and <code>api.epss_movers_24h</code>
          </div>
        </div>
      </section>

      <section style={{ marginTop: 16, display: "grid", gridTemplateColumns: "1.15fr 0.85fr", gap: 12 }}>
        {/* Top EPSS */}
        <div className="tb-card" style={{ padding: 12 }}>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 900 }}>Top EPSS (latest)</h2>
          <div style={{ marginTop: 10, display: "grid", gap: 10 }}>
            {top.slice(0, 80).map((r) => (
              <div
                key={r.cve_id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "140px 80px 70px 1fr",
                  gap: 10,
                  alignItems: "baseline",
                  padding: "10px 10px",
                  borderRadius: 14,
                  border: "1px solid rgba(255,255,255,0.10)",
                  background: "rgba(255,255,255,0.02)",
                }}
              >
                <Link href={`/cve/${r.cve_id}`} style={{ fontWeight: 950 }}>
                  {r.cve_id}
                </Link>
                <div style={{ fontSize: 12, opacity: 0.85 }}>
                  <span style={{ opacity: 0.7 }}>epss</span> <b>{fmtNum(r.epss, 4)}</b>
                </div>
                <div style={{ fontSize: 12, opacity: 0.85 }}>
                  <span style={{ opacity: 0.7 }}>cvss</span> <b>{fmtNum(r.cvss_base, 1)}</b>
                </div>
                <div
                  style={{
                    fontSize: 12,
                    opacity: 0.78,
                    overflow: "hidden",
                    display: "-webkit-box",
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: "vertical",
                    lineHeight: 1.35,
                  }}
                >
                  {r.description_en ?? ""}
                </div>
              </div>
            ))}

            {topErr ? (
              <div style={{ opacity: 0.85, padding: 8 }}>
                <div style={{ fontWeight: 900 }}>Failed to load top EPSS</div>
                <div style={{ marginTop: 6, fontFamily: "ui-monospace", whiteSpace: "pre-wrap", opacity: 0.8 }}>
                  {topErr}
                </div>
                <div style={{ marginTop: 6, opacity: 0.8 }}>
                  Ensure PostgREST exposes <code>api.epss_top_latest</code>.
                </div>
              </div>
            ) : top.length === 0 ? (
              <div style={{ opacity: 0.8, padding: 8 }}>
                No EPSS rows found.
              </div>
            ) : null}
          </div>
        </div>

        {/* Movers */}
        <div className="tb-card" style={{ padding: 12 }}>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 900 }}>EPSS movers (24h)</h2>
          <div style={{ marginTop: 10, display: "grid", gap: 10 }}>
            {movers.slice(0, 80).map((r, idx) => (
              <div
                key={`${r.cve_id ?? "null"}-${idx}`}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 70px",
                  gap: 10,
                  alignItems: "baseline",
                  padding: "10px 10px",
                  borderRadius: 14,
                  border: "1px solid rgba(255,255,255,0.10)",
                  background: "rgba(255,255,255,0.02)",
                }}
              >
                {r.cve_id ? (
                  <Link href={`/cve/${r.cve_id}`} style={{ fontWeight: 950 }}>
                    {r.cve_id}
                  </Link>
                ) : (
                  <span style={{ fontWeight: 900, opacity: 0.7 }}>—</span>
                )}
                <div style={{ fontSize: 12, opacity: 0.85, textAlign: "right" }}>
                  <span style={{ opacity: 0.7 }}>Δ</span> <b>{fmtNum(r.delta, 4)}</b>
                </div>

                <div style={{ gridColumn: "1 / -1", fontSize: 12, opacity: 0.75 }}>
                  today {fmtNum(r.epss_today, 4)} · yday {fmtNum(r.epss_yday, 4)}
                </div>
              </div>
            ))}

            {moversErr ? (
              <div style={{ opacity: 0.85, padding: 8 }}>
                <div style={{ fontWeight: 900 }}>Failed to load EPSS movers</div>
                <div style={{ marginTop: 6, fontFamily: "ui-monospace", whiteSpace: "pre-wrap", opacity: 0.8 }}>
                  {moversErr}
                </div>
                <div style={{ marginTop: 6, opacity: 0.8 }}>
                  Ensure PostgREST exposes <code>api.epss_movers_24h</code>.
                  <div style={{ marginTop: 4 }}>
                    In SQL: <code>create or replace view api.epss_movers_24h as select * from v_epss_movers_24h;</code>
                  </div>
                </div>
              </div>
            ) : movers.length === 0 ? (
              <div style={{ opacity: 0.8, padding: 8 }}>
                No movers found. This is expected if your DB only has one distinct <code>epss_daily.as_of</code> snapshot.
              </div>
            ) : null}
          </div>
        </div>
      </section>
    </main>
  );
}
