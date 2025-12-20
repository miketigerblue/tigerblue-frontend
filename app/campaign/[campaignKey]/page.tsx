import { getCampaignCves, getCampaignItems } from "@/lib/queries";
import Link from "next/link";

export default async function CampaignPage({
  params,
}: {
  params: Promise<{ campaignKey: string }>;
}) {
  const { campaignKey: encoded } = await params;
  const campaignKey = decodeURIComponent(encoded);

  const [cves, items] = await Promise.all([
    getCampaignCves(campaignKey, 100),
    getCampaignItems(campaignKey, 200),
  ]);

  return (
    <main style={{ padding: 24 }}>
      <Link href="/now" style={{ opacity: 0.75 }}>
        ← Now
      </Link>
      <h1 style={{ marginTop: 10, fontSize: 22, fontWeight: 800 }}>{campaignKey}</h1>

      <section style={{ marginTop: 24 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700 }}>CVEs</h2>
        {cves.length === 0 ? (
          <p style={{ opacity: 0.8, marginTop: 10 }}>No CVEs associated with this campaign.</p>
        ) : (
          <ul style={{ marginTop: 12, display: "grid", gap: 10 }}>
            {cves.map((c) => (
              <li key={c.cve_id} style={{ border: "1px solid #ddd", borderRadius: 14, padding: 12 }}>
                <Link href={`/cve/${c.cve_id}`} style={{ fontWeight: 800 }}>
                  {c.cve_id}
                </Link>
                <div style={{ marginTop: 6, fontSize: 13, opacity: 0.8 }}>
                  CVSS {c.cvss_base ?? "–"} · EPSS {c.epss ?? "–"} · items {c.item_count} · last {c.last_seen}
                </div>
                {c.description_en ? <p style={{ marginTop: 8, fontSize: 14, lineHeight: 1.4 }}>{c.description_en}</p> : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section style={{ marginTop: 32 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700 }}>Items</h2>
        <ul style={{ marginTop: 12, display: "grid", gap: 10 }}>
          {items.map((it) => (
            <li key={it.analysis_id} style={{ border: "1px solid #ddd", borderRadius: 14, padding: 12 }}>
              <Link href={`/item/${it.analysis_id}`} style={{ fontWeight: 700 }}>
                {it.title}
              </Link>
              <div style={{ marginTop: 6, fontSize: 13, opacity: 0.8 }}>
                {it.source_name} · {it.analysed_at} · iocs {it.ioc_count} · cves {it.cve_count}
              </div>
              <p style={{ marginTop: 8, fontSize: 14, lineHeight: 1.4 }}>{it.summary_impact}</p>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
