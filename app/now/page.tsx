import { getNowItems } from "@/lib/queries";
import SignalMapClient from "./SignalMapClient";

export default async function NowPage() {
  let items: Awaited<ReturnType<typeof getNowItems>> = [];
  let warning: string | null = null;

  try {
    items = await getNowItems(220);
  } catch {
    warning =
      "Data source temporarily unavailable (PostgREST schema cache warmup). Showing empty map.";
  }

  // Map expects a stable id; analysis_id is the PostgREST primary key.
  const initial = items.map((it) => ({
    id: it.analysis_id,
    title: it.title,
    source_name: it.source_name,
    published: it.published,
    link: it.link,
    severity_level: it.severity_level,
    severity_rank: it.severity_rank,
    summary_impact: it.summary_impact,
  }));

  return (
    <>
      {warning ? (
        <div
          style={{
            position: "fixed",
            left: 16,
            bottom: 16,
            zIndex: 50,
            padding: "10px 12px",
            borderRadius: 14,
            border: "1px solid rgba(255,255,255,0.12)",
            background: "rgba(10, 12, 18, 0.72)",
            backdropFilter: "blur(10px)",
            color: "rgba(230,236,255,0.9)",
            fontSize: 12,
            maxWidth: 520,
          }}
        >
          {warning}
        </div>
      ) : null}
      <SignalMapClient initial={initial} />
    </>
  );
}
