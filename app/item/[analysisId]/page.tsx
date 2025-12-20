import { pgGet } from "@/lib/postgrest";
import Link from "next/link";

export default async function ItemPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;

  const rows = await pgGet<any[]>(
    "/analysis_entries",
    { analysis_id: `eq.${analysisId}`, select: "*" },
    { revalidate: 60, tags: ["item", analysisId] }
  );

  const item = rows[0];
  if (!item) return <main style={{ padding: 24 }}>Not found</main>;

  return (
    <main style={{ padding: 24, maxWidth: 980, margin: "0 auto" }}>
      <Link href="/now" style={{ opacity: 0.8 }}>
        ← Now
      </Link>
      <h1 style={{ marginTop: 10, fontSize: 22, fontWeight: 900 }}>{item.title}</h1>
      <div style={{ marginTop: 8, fontSize: 13, opacity: 0.8 }}>
        {item.source_name} · analysed {item.analysed_at} · published {item.published ?? "–"}
      </div>

      <section style={{ marginTop: 16 }}>
        <h2 style={{ fontSize: 16, fontWeight: 800 }}>Summary</h2>
        <div className="tb-card" style={{ marginTop: 8, padding: 12 }}>
          <p style={{ margin: 0, lineHeight: 1.55 }}>{item.summary_impact}</p>
        </div>
      </section>

      <section style={{ marginTop: 16 }}>
        <h2 style={{ fontSize: 16, fontWeight: 800 }}>Content</h2>
        <div
          className="tb-card tb-prose"
          style={{ marginTop: 8, padding: 12 }}
          dangerouslySetInnerHTML={{ __html: item.content }}
        />
      </section>
    </main>
  );
}
