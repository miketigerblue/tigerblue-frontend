export type CampaignLatestSeen = {
  campaign_key: string;
  last_seen: string;
  cve_count: number;
  item_mentions: number;
};

export type CampaignCveRollup = {
  campaign_key?: string;
  cve_id: string;
  epss: number | null;
  cvss_base: number | null;
  item_count: number;
  mention_count?: number;
  first_seen: string;
  last_seen: string;
  description_en: string | null;
};

export type AnalysisEntryLite = {
  analysis_id: string;
  analysed_at: string;
  published?: string;
  title: string;
  link?: string;
  source_name: string;
  severity_level?: string;
  severity_rank?: number;
  ioc_count: number;
  cve_count: number;
  action_count: number;
  summary_impact: string;
  exploit_references?: any;
};

export type AnalysisEntryCampaign = AnalysisEntryLite & {
  campaign_key: string;
};

// ---------------------------
// Number 2 (Hourly Sitrep)
// ---------------------------

export type Number2PriorityBand = "low" | "medium" | "high" | "critical";

export type Number2PriorityIndex = {
  score: number;
  band: Number2PriorityBand;
  why: string;
  components: {
    likelihood: { score: number; why: string };
    impact: { score: number; why: string };
    confidence: { score: number; why: string };
    recency: { score: number; why: string };
    relevance: { score: number; why: string };
  };
};

export type Number2SourceItemEvidence = {
  cve_ids: string[];
  exploit_references: string[];
  ioc_count: number;
};

export type Number2SourceItemRef = {
  analysis_id?: string | null;
  guid: string;
  source_name?: string | null;
  source_url?: string | null;
  item_url?: string | null;
  item_type?: string;
  analysed_at?: string | null;
  evidence: Number2SourceItemEvidence;
};

export type Number2TTP = {
  framework: string;
  id?: string | null;
  name?: string | null;
  confidence: "low" | "medium" | "high";
};

export type Number2CveEntry = {
  cve_id: string;
  cvss?: any;
  kev?: any;
  exploit_status?: string;
  affected?: any;
};

export type Number2ClusterBrief = {
  cluster_id: string;
  title: string;
  cluster_type: string;
  priority_index: Number2PriorityIndex;
  time: { first_seen: string; last_seen: string };
  signals_vs_facts: { signal_items: number; fact_items: number; notes: string };
  intelligence: {
    cves: Number2CveEntry[];
    actors: string[];
    products: string[];
    campaigns: string[];
    malware_families: string[];
    ttps: Number2TTP[];
    attack_vectors: string[];
    recommended_actions: string[];
    mitigations: string[];
    iocs: any;
  };
  source_items: Number2SourceItemRef[];
};

export type Number2HourlySitrep = {
  schema_version: string;
  report_id: string;
  generated_at: string;
  window: { start: string; end: string; duration_minutes: number };
  inputs: {
    analysis_rows_considered: number;
    analysis_rows_included: number;
    sources: { source_name: string; count: number }[];
    note: string;
  };
  executive_summary: {
    headline: string;
    key_points: string[];
    numbers: {
      clusters_total: number;
      clusters_priority_high: number;
      clusters_priority_medium: number;
      cves_mentioned: number;
      kev_mentions: number;
    };
  };
  ranked_priorities: Number2ClusterBrief[];
  source_transparency?: any;
  generation?: any;
};

export type Number2SitrepRow = {
  window_start: string;
  window_end: string;
  generated_at: string;
  pipeline_version: string;
  report: Number2HourlySitrep;
};

// ---------------------------
// Number 2 (Daily Insights)
// ---------------------------

export type Number2DailyInsightsRow = {
  // Typically a single row (array length 1)
  insights: {
    window: { start: string; end: string; sitreps: number };
    risk_temperature: {
      clusters_total: number;
      clusters_70_plus: number;
      clusters_50_69: number;
      clusters_under_50: number;
      by_band?: Record<string, number>;
    };
    top_clusters: Array<{
      title: string;
      score?: number;
      band?: string;
      items?: number;
      sources?: number;
      cves?: number;
    }>;
    top_sources: Array<{ source_name: string; items: number; hours_seen: number }>;
    hot_cves: Array<{ cve_id: string; mentions: number; hours_seen: number }>;
    attack_vector_themes: Array<{ attack_vector: string; mentions: number; hours_seen: number }>;

    // Future-proofing: allow extra keys without breaking typing
    [k: string]: any;
  };
};
