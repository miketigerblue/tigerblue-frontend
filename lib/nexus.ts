import "server-only";

const BASE = process.env.NEXUS_BASE;

if (!BASE) {
  throw new Error("Missing NEXUS_BASE");
}

export type NexusSearchRequest = {
  text: string;
  n_results?: number;
};

export type NexusSearchResult = {
  id: string;
  score: number | null;
  title: string;
  url: string;
  source: string;
  published: string;
  severity: string;
  summary_impact: string;
  relevance: string;
  cve_references: string;
  key_iocs: string;
  recommended_actions: string;
};

export type NexusSearchResponse = {
  query: string;
  count: number;
  results: NexusSearchResult[];
};

export async function nexusSearch(
  req: NexusSearchRequest,
  opts: { revalidate?: number; tags?: string[] } = {}
): Promise<NexusSearchResponse> {
  const res = await fetch(new URL("/api/v1/search", BASE), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      text: req.text,
      n_results: req.n_results ?? 10,
    }),
    next: {
      revalidate: opts.revalidate ?? 60,
      tags: opts.tags,
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `Nexus search failed ${res.status} ${res.statusText} (${BASE})\n${text}`
    );
  }

  return (await res.json()) as NexusSearchResponse;
}
