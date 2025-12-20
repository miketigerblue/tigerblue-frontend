import Link from "next/link";
import { getDailyInsightsLatest, getSitrepHistory, getSitrepLatest } from "@/lib/queries";
import SitrepClient from "./sitrep-client";

export default async function SitrepPage() {
  const [latest, history, insights] = await Promise.all([
    getSitrepLatest().catch(() => null),
    getSitrepHistory(24).catch(() => []),
    getDailyInsightsLatest().catch(() => null),
  ]);

  return (
    <main
      className="tb-sitrep"
      style={{
        minHeight: "100vh",
        padding: 20,
        background:
          "radial-gradient(900px 600px at 18% 20%, rgba(0, 255, 196, 0.12), transparent 60%), radial-gradient(900px 700px at 75% 25%, rgba(255, 0, 212, 0.10), transparent 55%), radial-gradient(1100px 900px at 50% 85%, rgba(80, 140, 255, 0.10), transparent 60%), #050610",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "baseline",
          gap: 14,
          flexWrap: "wrap",
          marginBottom: 14,
        }}
      >
        <Link href="/now" style={{ opacity: 0.85 }}>
          ← Now
        </Link>
        <h1 style={{ margin: 0, fontSize: 26, fontWeight: 950, letterSpacing: 0.2 }}>
          Sitrep
        </h1>
        <div style={{ fontSize: 12, opacity: 0.7 }}>
          Hourly situational awareness · clustered + ranked · transparent scoring
        </div>

        <div style={{ marginLeft: "auto", display: "flex", gap: 10, flexWrap: "wrap" }}>
          <Link href="/timeline" style={{ opacity: 0.85 }}>
            Timeline
          </Link>
          <Link href="/kev" style={{ opacity: 0.85 }}>
            KEV
          </Link>
          <Link href="/epss" style={{ opacity: 0.85 }}>
            EPSS
          </Link>
        </div>
      </header>

      {!latest ? (
        <div
          className="tb-card"
          style={{
            padding: 14,
            border: "1px solid rgba(255,173,59,0.35)",
            background: "rgba(255,173,59,0.06)",
            fontSize: 12,
            opacity: 0.9,
          }}
        >
          No sitrep available yet. (The hourly worker may still be warming up.)
          <div style={{ marginTop: 8, opacity: 0.8 }}>
            Expected endpoint: <code>/number2_hourly_sitreps_latest</code>
          </div>
        </div>
      ) : null}

      <SitrepClient latest={latest} history={history} insights={insights} />
    </main>
  );
}
