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

export async function nexusSearchClient(
  text: string,
  n_results = 10
): Promise<NexusSearchResponse> {
  const res = await fetch("/api/nexus/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, n_results }),
  });

  if (!res.ok) {
    const msg = await res.text().catch(() => "");
    throw new Error(`Nexus proxy failed: ${res.status} ${res.statusText}\n${msg}`);
  }

  return (await res.json()) as NexusSearchResponse;
}
