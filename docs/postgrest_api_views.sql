-- TigerBlue / Threat Kitty
-- PostgREST exposes ONLY the `api` schema.
-- Run these in your DB (as a role that can create views in `api`).
-- After creating/updating views, reload PostgREST schema cache if needed.

-- =========================
-- KEV
-- =========================

-- KEV lives in the typed `public.cve_kev` table (one row per CVE, `withdrawn_at`
-- set when CISA removes an entry). The old `cve_enriched` rows with
-- source = 'CISA-KEV' are unmaintained remnants — nothing writes them any more,
-- so do not read them.
create or replace view api.kev_cves_lite as
select
  k.cve_id,
  k.last_seen_at as modified,
  'CISA-KEV'::text as source,

  -- Typed KEV fields (CISA)
  k.date_added,
  k.due_date,
  k.vendor_project as vendor,
  k.product,
  k.vulnerability_name,
  k.short_description,
  k.required_action,
  case when k.known_ransomware_use then 'Known' else 'Unknown' end
    as known_ransomware_campaign_use,
  k.known_ransomware_use,
  k.notes,
  to_jsonb(k.cwes) as cwes,

  -- Full KEV JSON as received from CISA
  k.raw as kev_json
from public.cve_kev k
where k.withdrawn_at is null;

-- =========================
-- NVD (lite)
-- =========================

-- One row per CVE from the NVD source. `cvss_base` is a mixed-version column
-- (v3.1 preferred, then v3.0, v4.0, v2.0) — always read it alongside
-- `cvss_version`. v2 has no Critical band: a v2 9.x is HIGH.
-- `vuln_status` / `published` are populated as NVD re-emits records, so
-- predicates must be NULL-safe (`is distinct from 'Rejected'`).
create or replace view api.nvd_cves_lite as
select
  ce.cve_id,
  ce.published,
  ce.modified,
  ce.vuln_status,
  ce.source_identifier,
  ce.cve_tags,
  ce.cvss_base,
  ce.cvss_version,
  case when ce.cvss_version in ('3.0', '3.1') then ce.cvss_base end as cvss_v3,
  case
    when ce.cvss_base is null then null
    when ce.cvss_base >= 9.0 and ce.cvss_version is distinct from '2.0' then 'CRITICAL'
    when ce.cvss_base >= 7.0 then 'HIGH'
    when ce.cvss_base >= 4.0 then 'MEDIUM'
    when ce.cvss_base > 0.0 then 'LOW'
    else 'NONE'
  end as cvss_severity,
  ce.epss,
  ce.ssvc_exploitation,
  ce.ssvc_automatable,
  ce.ssvc_technical_impact,
  (
    select d->>'value'
    from jsonb_array_elements(coalesce(ce.json->'descriptions', '[]'::jsonb)) d
    where d->>'lang' = 'en'
    limit 1
  ) as description_en
from public.cve_enriched ce
where ce.source = 'NVD';

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

-- Top EPSS “right now”, decorated from `api.nvd_cves_lite`.
-- Rejected CVEs are dropped here (NULL-safe: most rows have no status yet).
create or replace view api.epss_top_latest as
select
  e.cve_id,
  e.as_of,
  e.epss,
  e.percentile,
  n.cvss_base,
  n.cvss_version,
  n.cvss_severity,
  n.ssvc_exploitation,
  n.vuln_status,
  n.published,
  n.modified,
  n.description_en
from api.epss_latest e
left join api.nvd_cves_lite n
  on n.cve_id = e.cve_id
where n.vuln_status is distinct from 'Rejected';

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
-- - Rejected CVEs are NOT filtered out here: the detail page should render them
--   with `vuln_status = 'Rejected'` rather than 404.
-- - EPSS is joined from `api.epss_latest` (latest score per CVE).
-- - KEV is joined from `api.kev_cves_lite` (CISA KEV listing + typed fields);
--   `ssvc_exploitation = 'active'` is NVD's own corroborating exploitation signal
--   and `'poc'` flags a public proof-of-concept short of KEV.
-- - Mention/campaign stats are joined/aggregated from the api views/matviews.
create or replace view api.cve_detail as
with
  nvd as (
    select
      ce.cve_id,
      ce.published,
      ce.modified,
      ce.vuln_status,
      ce.source_identifier,
      ce.cve_tags,
      ce.cvss_base,
      ce.cvss_version,
      ce.cvss_v3,
      ce.cvss_severity,
      ce.epss,
      ce.ssvc_exploitation,
      ce.ssvc_automatable,
      ce.ssvc_technical_impact,
      ce.description_en,
      raw.json
    from api.nvd_cves_lite ce
    join public.cve_enriched raw
      on raw.cve_id = ce.cve_id and raw.source = 'NVD'
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
  nvd.published,
  nvd.modified,
  nvd.vuln_status,
  nvd.source_identifier,
  nvd.cve_tags,
  nvd.cvss_base,
  nvd.cvss_version,
  nvd.cvss_v3,
  nvd.cvss_severity,
  nvd.ssvc_exploitation,
  nvd.ssvc_automatable,
  nvd.ssvc_technical_impact,

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
  k.known_ransomware_use,
  k.notes,

  m.mention_count,
  m.last_seen,

  c.campaign_count,
  c.campaign_item_count,
  c.campaign_mention_count,
  c.campaign_first_seen,
  c.campaign_last_seen,

  nvd.description_en,

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
