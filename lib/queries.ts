import "server-only";
import { pgGet } from "./postgrest";
import type {
  CampaignLatestSeen,
  CampaignCveRollup,
  AnalysisEntryCampaign,
  AnalysisEntryLite,
  Number2DailyInsightsRow,
  Number2SitrepRow,
} from "./types";

export type TimelineItem = {
  analysis_id: string;
  analysed_at: string;
  published?: string;
  title: string;
  link?: string;
  source_name: string;
  severity_level?: string;
  severity_rank?: number;
  cve_count?: number;
  summary_impact: string;
};

export type NvdTimelineItem = {
  cve_id: string;
  mention_count: number;
  modified: string | null;
  cvss_base: number | null;
  epss: number | null;
  description_en: string | null;
};

export type NvdLiteRow = {
  cve_id: string;
  modified: string | null;
  cvss_base: number | null;
  epss: number | null;
  description_en: string | null;
};

export async function getNvdLiteForCve(cveId: string) {
  return pgGet<NvdLiteRow[]>(
    "/nvd_cves_lite",
    {
      cve_id: `eq.${cveId}`,
      limit: 1,
      select: "cve_id,modified,cvss_base,epss,description_en",
    },
    { revalidate: 3600, tags: ["cve", cveId, "nvd-lite"] }
  ).then((rows) => rows[0] ?? null);
}

export type SeverityBySource7d = {
  source_name: string;
  severity_level: string;
  cnt: number;
};

export async function getNowCampaigns(limit = 50) {
  return pgGet<CampaignLatestSeen[]>(
    "/campaign_latest_seen",
    {
      order: "last_seen.desc",
      limit,
      select: "campaign_key,last_seen,cve_count,item_mentions",
    },
    { revalidate: 30, tags: ["now"] }
  );
}

export async function getNowItems(limit = 30) {
  return pgGet<AnalysisEntryLite[]>(
    "/analysis_entries_lite",
    {
      order: "analysed_at.desc",
      limit,
      select:
        "analysis_id,analysed_at,published,title,link,source_name,severity_rank,severity_level,ioc_count,cve_count,action_count,summary_impact,exploit_references",
    },
    { revalidate: 30, tags: ["now"] }
  );
}

export async function getSitrepLatest() {
  return pgGet<Number2SitrepRow[]>(
    "/number2_hourly_sitreps_latest",
    {
      order: "window_start.desc",
      limit: 1,
      select: "window_start,window_end,generated_at,pipeline_version,report",
    },
    { revalidate: 30, tags: ["sitrep", "sitrep-latest"] }
  ).then((rows) => rows[0] ?? null);
}

export async function getSitrepHistory(limit = 24) {
  return pgGet<Number2SitrepRow[]>(
    "/number2_hourly_sitreps",
    {
      order: "window_start.desc",
      limit,
      select: "window_start,window_end,generated_at,pipeline_version,report",
    },
    { revalidate: 60, tags: ["sitrep", "sitrep-history"] }
  );
}

export async function getDailyInsightsLatest() {
  return pgGet<Number2DailyInsightsRow[]>(
    "/number2_daily_insights_latest",
    { limit: 1, select: "insights" },
    { revalidate: 60, tags: ["sitrep", "daily-insights"] }
  ).then((rows) => rows[0] ?? null);
}

export async function getCampaignItems(campaignKey: string, limit = 200) {
  return pgGet<AnalysisEntryCampaign[]>(
    "/analysis_entries_campaign",
    {
      campaign_key: `eq.${campaignKey}`,
      order: "analysed_at.desc",
      limit,
      select:
        "analysis_id,analysed_at,published,title,source_name,ioc_count,cve_count,action_count,summary_impact,exploit_references,campaign_key",
    },
    { revalidate: 60, tags: ["campaign", campaignKey] }
  );
}

export async function getCampaignCves(campaignKey: string, limit = 100) {
  return pgGet<CampaignCveRollup[]>(
    "/campaign_cve_rollups",
    {
      campaign_key: `eq.${campaignKey}`,
      order: "epss.desc.nullslast,cvss_base.desc.nullslast,last_seen.desc",
      limit,
      select:
        "cve_id,epss,cvss_base,item_count,mention_count,first_seen,last_seen,description_en",
    },
    { revalidate: 60, tags: ["campaign", campaignKey] }
  );
}

export async function getCveCampaigns(cveId: string, limit = 50) {
  return pgGet<
    {
      campaign_key: string;
      item_count: number;
      mention_count: number;
      last_seen: string;
      epss: number | null;
      cvss_base: number | null;
    }[]
  >(
    "/campaign_cve_rollups",
    {
      cve_id: `eq.${cveId}`,
      order: "last_seen.desc",
      limit,
      select: "campaign_key,item_count,mention_count,last_seen,epss,cvss_base",
    },
    { revalidate: 120, tags: ["cve", cveId] }
  );
}

export async function getLatestAnalysedAt(): Promise<string | null> {
  return pgGet<{ analysed_at: string }[]>(
    "/analysis_entries_lite",
    {
      order: "analysed_at.desc",
      limit: 1,
      select: "analysed_at",
    },
    // Keep this relatively low so the UI feels live while backfill catches up.
    { revalidate: 5, tags: ["timeline"] }
  ).then((rows) => rows[0]?.analysed_at ?? null);
}

export async function getTimelineItemsSince(
  sinceIso: string,
  limit = 800,
  untilIso?: string
): Promise<TimelineItem[]> {
  const base = {
    order: "analysed_at.desc",
    limit,
    select:
      "analysis_id,analysed_at,published,title,link,source_name,severity_level,severity_rank,cve_count,summary_impact",
  };

  return pgGet<TimelineItem[]>(
    "/analysis_entries_lite",
    untilIso
      ? {
          ...base,
          and: `(analysed_at.gte.${sinceIso},analysed_at.lte.${untilIso})`,
        }
      : {
          ...base,
          analysed_at: `gte.${sinceIso}`,
        },
    // Keep this relatively low so the UI feels live while backfill catches up.
    { revalidate: 5, tags: ["timeline"] }
  );
}

export async function getStatsSeverityBySource7d() {
  return pgGet<SeverityBySource7d[]>(
    "/stats_severity_by_source_7d",
    { select: "source_name,severity_level,cnt", order: "cnt.desc", limit: 1000 },
    { revalidate: 300, tags: ["timeline"] }
  );
}

export async function getNvdTimelineItemsSince(
  sinceIso: string,
  limit = 5000,
  untilIso?: string
): Promise<NvdTimelineItem[]> {
  // PostgREST commonly enforces a max rows cap per request. To avoid truncating
  // the 7-day window, page through results using offset.
  const pageSize = Math.min(1000, limit);
  const out: NvdTimelineItem[] = [];

  for (let offset = 0; out.length < limit; offset += pageSize) {
    const base = {
      order: "modified.desc",
      limit: pageSize,
      offset,
      select: "cve_id,modified,cvss_base,epss,description_en",
    };

    const page = await pgGet<NvdTimelineItem[]>(
      "/nvd_cves_lite",
      untilIso
        ? {
            ...base,
            and: `(modified.gte.${sinceIso},modified.lte.${untilIso})`,
          }
        : {
            ...base,
            modified: `gte.${sinceIso}`,
          },
      // CVE data updates frequently; keep this snappy.
      { revalidate: 30, tags: ["timeline", "nvd"] }
    );

    // nvd_cves_lite doesn't include mention_count; keep it as 0.
    out.push(
      ...page.map((p) => ({
        ...p,
        mention_count: 0,
      }))
    );

    if (page.length < pageSize) break;
  }

  return out;
}

export type MentionedCveItem = {
  cve_id: string;
  mention_count: number;
  last_seen: string;
  cvss_base: number | null;
  epss: number | null;
  modified: string | null;
  description_en: string | null;
};

export async function getMentionedCvesSince(
  sinceIso: string,
  limit = 2000
): Promise<MentionedCveItem[]> {
  return pgGet<MentionedCveItem[]>(
    "/analysis_cves_enriched_lite",
    {
      last_seen: `gte.${sinceIso}`,
      order: "last_seen.desc",
      limit,
      select: "cve_id,mention_count,last_seen,cvss_base,epss,modified,description_en",
    },
    { revalidate: 30, tags: ["timeline", "mentioned-cves"] }
  );
}

export type CveDetailRow = {
  cve_id: string;
  modified: string | null;
  cvss_base: number | null;
  epss: number | null;
  epss_percentile?: number | null;
  epss_as_of?: string | null;
  description_en?: string | null;
  json?: any;

  // Optional enrichment fields when served from api.cve_detail
  in_kev?: boolean | null;
  date_added?: string | null;
  due_date?: string | null;
  vendor?: string | null;
  product?: string | null;
  vulnerability_name?: string | null;
  short_description?: string | null;
  required_action?: string | null;
  known_ransomware_campaign_use?: string | null;
  notes?: string | null;

  mention_count?: number | null;
  last_seen?: string | null;

  campaign_count?: number | null;
  campaign_item_count?: number | null;
  campaign_mention_count?: number | null;
  campaign_first_seen?: string | null;
  campaign_last_seen?: string | null;
};

export async function getCveDetail(cveId: string): Promise<CveDetailRow | null> {
  // Prefer the one-stop endpoint when available.
  // Fallback chain is kept for backward-compat until the backend view is deployed.
  const tags = ["cve", cveId];

  const getOneOrNull = async (
    path: string,
    params: Record<string, string | number | boolean | undefined>
  ) => {
    try {
      const rows = await pgGet<CveDetailRow[]>(path, params, {
        revalidate: 3600,
        tags,
      });
      return rows[0] ?? null;
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      // Missing relation / endpoint (common during staged rollouts)
      if (msg.includes(" GET failed 404 ")) return null;
      throw e;
    }
  };

  const fromDetail = await getOneOrNull("/cve_detail", {
    cve_id: `eq.${cveId}`,
    select:
      "cve_id,modified,cvss_base,epss,epss_percentile,epss_as_of,description_en,json,in_kev,date_added,due_date,vendor,product,vulnerability_name,short_description,required_action,known_ransomware_campaign_use,notes,mention_count,last_seen,campaign_count,campaign_item_count,campaign_mention_count,campaign_first_seen,campaign_last_seen",
    limit: 1,
  });
  if (fromDetail) return fromDetail;

  const fromNvd = await getOneOrNull("/nvd_cves", {
    cve_id: `eq.${cveId}`,
    select: "cve_id,cvss_base,epss,modified,json",
    limit: 1,
  });
  if (fromNvd) return fromNvd;

  return getOneOrNull("/analysis_cves_enriched", {
    cve_id: `eq.${cveId}`,
    select: "cve_id,mention_count,last_seen,cvss_base,epss,modified,json",
    limit: 1,
  });
}

export type CveEpssLatestRow = {
  cve_id: string;
  as_of: string;
  epss: number;
  percentile: number | null;
};

export async function getEpssLatestForCve(cveId: string) {
  return pgGet<CveEpssLatestRow[]>(
    "/epss_latest",
    {
      cve_id: `eq.${cveId}`,
      order: "as_of.desc",
      limit: 1,
      select: "cve_id,as_of,epss,percentile",
    },
    { revalidate: 3600, tags: ["cve", cveId, "epss"] }
  ).then((rows) => rows[0] ?? null);
}

export type KevLiteRow = {
  cve_id: string;
  date_added: string | null;
  due_date: string | null;
  vendor: string | null;
  product: string | null;
  vulnerability_name: string | null;
  short_description: string | null;
  required_action: string | null;
  known_ransomware_campaign_use: string | null;
  notes: string | null;
};

export async function getKevLiteForCve(cveId: string) {
  return pgGet<KevLiteRow[]>(
    "/kev_cves_lite",
    {
      cve_id: `eq.${cveId}`,
      limit: 1,
      select:
        "cve_id,date_added,due_date,vendor,product,vulnerability_name,short_description,required_action,known_ransomware_campaign_use,notes",
    },
    { revalidate: 3600, tags: ["cve", cveId, "kev"] }
  ).then((rows) => rows[0] ?? null);
}

export type KevCveItem = {
  cve_id: string;
  modified: string;
  source: string;
  date_added: string | null;
  due_date: string | null;
  vendor: string | null;
  product: string | null;
  vulnerability_name: string | null;
  short_description: string | null;
  required_action: string | null;
  known_ransomware_campaign_use: string | null;
  notes: string | null;
  cwes: any;
  kev_json: any;
};

export async function getKevCves(limit = 200) {
  return pgGet<KevCveItem[]>(
    "/kev_cves_lite",
    {
      order: "date_added.desc.nullslast",
      limit,
      select:
        "cve_id,modified,source,date_added,due_date,vendor,product,vulnerability_name,short_description,required_action,known_ransomware_campaign_use,notes,cwes,kev_json",
    },
    { revalidate: 300, tags: ["kev"] }
  );
}

export type EpssTopItem = {
  cve_id: string;
  as_of: string;
  epss: number;
  percentile: number | null;
  cvss_base: number | null;
  modified: string | null;
  description_en: string | null;
};

export async function getEpssTopLatest(limit = 200) {
  return pgGet<EpssTopItem[]>(
    "/epss_top_latest",
    {
      order: "epss.desc.nullslast",
      limit,
      select: "cve_id,as_of,epss,percentile,cvss_base,modified,description_en",
    },
    { revalidate: 300, tags: ["epss"] }
  );
}

export type EpssMoverItem = {
  cve_id: string | null;
  epss_today: number | null;
  epss_yday: number | null;
  delta: number | null;
  percentile_today: number | null;
  percentile_yday: number | null;
};

export async function getEpssMovers24h(limit = 200) {
  return pgGet<EpssMoverItem[]>(
    "/epss_movers_24h",
    {
      order: "delta.desc.nullslast",
      limit,
      select:
        "cve_id,epss_today,epss_yday,delta,percentile_today,percentile_yday",
    },
    { revalidate: 300, tags: ["epss"] }
  );
}
