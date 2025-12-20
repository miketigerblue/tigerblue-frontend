import { NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { nexusSearch } from "@/lib/nexus";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const body = (await req.json().catch(() => null)) as
    | { text?: unknown; n_results?: unknown }
    | null;

  if (!body || typeof body.text !== "string" || body.text.trim().length === 0) {
    return NextResponse.json(
      { error: "Missing required field 'text'" },
      { status: 400 }
    );
  }

  const nRaw = body.n_results;
  const n =
    typeof nRaw === "number" && Number.isFinite(nRaw)
      ? Math.max(1, Math.min(25, Math.floor(nRaw)))
      : 10;

  try {
    const qHash = createHash("sha256").update(body.text).digest("hex").slice(0, 16);
    const data = await nexusSearch(
      { text: body.text, n_results: n },
      { revalidate: 30, tags: ["nexus", `q:${qHash}`] }
    );
    return NextResponse.json(data);
  } catch (e: any) {
    return NextResponse.json(
      { error: e?.message ?? "Nexus request failed" },
      { status: 502 }
    );
  }
}
