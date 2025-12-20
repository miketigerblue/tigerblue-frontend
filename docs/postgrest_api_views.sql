-- TigerBlue / Threat Kitty
-- PostgREST exposes ONLY the `api` schema.
-- Run these in your DB (as a role that can create views in `api`).
-- After creating/updating views, reload PostgREST schema cache if needed.

-- =========================
-- KEV
-- =========================

-- KEV rows are stored in `cve_enriched` with source = 'CISA-KEV'.
-- Expose a convenient, typed view for the frontend.
create or replace view api.kev_cves_lite as
select
  ce.cve_id,
  ce.modified,
  ce.source,

  -- Parsed KEV fields (CISA)
  (ce.json->>'dateAdded')::date as date_added,
  (ce.json->>'dueDate')::date as due_date,
  ce.json->>'vendorProject' as vendor,
  ce.json->>'product' as product,
  ce.json->>'vulnerabilityName' as vulnerability_name,
  ce.json->>'shortDescription' as short_description,
  ce.json->>'requiredAction' as required_action,
  ce.json->>'knownRansomwareCampaignUse' as known_ransomware_campaign_use,
  ce.json->>'notes' as notes,
  ce.json->'cwes' as cwes,

  -- Full KEV JSON (requested)
  ce.json as kev_json
from cve_enriched ce
where ce.source = 'CISA-KEV';

-- =========================
-- EPSS
-- =========================

-- Latest EPSS row per CVE.
-- NOTE: If this becomes heavy, convert to a materialized view and refresh daily.
create or replace view api.epss_latest as
select distinct on (e.cve_id)
  e.cve_id,
  e.as_of,
  e.epss,
  e.percentile,
  e.inserted_at
from epss_daily e
order by e.cve_id, e.as_of desc;

-- Top EPSS “right now”.
-- If `api.nvd_cves_lite` exists, join it to decorate with description/cvss/modified.
-- Otherwise, remove the join and keep EPSS-only fields.
create or replace view api.epss_top_latest as
select
  e.cve_id,
  e.as_of,
  e.epss,
  e.percentile,
  n.cvss_base,
  n.modified,
  n.description_en
from api.epss_latest e
left join api.nvd_cves_lite n
  on n.cve_id = e.cve_id;

-- EPSS movers view wrapper (this exists today outside `api`).
create or replace view api.epss_movers_24h as
select * from v_epss_movers_24h;

-- =========================
-- CVE detail (one-stop)
-- =========================

-- A single CVE detail endpoint designed for the frontend CVE page.
--
-- Notes:
-- - NVD JSON lives in `public.cve_enriched` with source = 'NVD' and a *flat* record shape
--   (top-level keys: id, descriptions, metrics, references, weaknesses, configurations...).
-- - EPSS is joined from `api.epss_latest` (latest score per CVE).
-- - KEV is joined from `api.kev_cves_lite` (CISA KEV listing + parsed fields).
-- - Mention/campaign stats are joined/aggregated from the api views/matviews.
create or replace view api.cve_detail as
with
  nvd as (
    select
      ce.cve_id,
      ce.modified,
      ce.cvss_base,
      ce.epss,
      ce.json
    from public.cve_enriched ce
    where ce.source = 'NVD'
  ),
  mentions as (
    select
      cve_id,
      sum(mention_count)::bigint as mention_count,
      max(last_seen) as last_seen
    from api.analysis_cves_enriched
    group by cve_id
  ),
  campaign as (
    select
      cve_id,
      count(*)::int as campaign_count,
      sum(item_count)::bigint as campaign_item_count,
      sum(mention_count)::bigint as campaign_mention_count,
      min(first_seen) as campaign_first_seen,
      max(last_seen) as campaign_last_seen
    from api.campaign_cve_rollups
    group by cve_id
  )
select
  nvd.cve_id,
  nvd.modified,
  nvd.cvss_base,

  coalesce(e.epss, nvd.epss) as epss,
  e.percentile as epss_percentile,
  e.as_of as epss_as_of,

  (k.cve_id is not null) as in_kev,
  k.date_added,
  k.due_date,
  k.vendor,
  k.product,
  k.vulnerability_name,
  k.short_description,
  k.required_action,
  k.known_ransomware_campaign_use,
  k.notes,

  m.mention_count,
  m.last_seen,

  c.campaign_count,
  c.campaign_item_count,
  c.campaign_mention_count,
  c.campaign_first_seen,
  c.campaign_last_seen,

  (
    select d->>'value'
    from jsonb_array_elements(coalesce(nvd.json->'descriptions', '[]'::jsonb)) d
    where d->>'lang' = 'en'
    limit 1
  ) as description_en,

  nvd.json
from nvd
left join api.epss_latest e
  on e.cve_id = nvd.cve_id
left join api.kev_cves_lite k
  on k.cve_id = nvd.cve_id
left join mentions m
  on m.cve_id = nvd.cve_id
left join campaign c
  on c.cve_id = nvd.cve_id;
