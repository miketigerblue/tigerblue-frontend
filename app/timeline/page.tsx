import {
  getLatestAnalysedAt,
  getNvdTimelineItemsSince,
  getTimelineItemsSince,
} from "@/lib/queries";
import TimelineClient from "./timeline-client";

function isoDaysBefore(anchorIso: string, days: number) {
  const d = new Date(anchorIso);
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString();
}

function startOfUtcDayIso(anchorIso: string) {
  const d = new Date(anchorIso);
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString();
}

type SearchParams = {
  from?: string;
  to?: string;
};

function isIsoDay(s?: string) {
  return !!s && /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function startOfUtcDayFromYmd(ymd: string) {
  return `${ymd}T00:00:00.000Z`;
}

function endOfUtcDayFromYmd(ymd: string) {
  return `${ymd}T23:59:59.999Z`;
}

export default async function TimelinePage({
  searchParams,
}: {
  searchParams?: Promise<SearchParams>;
}) {
  const sp = (await searchParams) ?? {};

  const nowIso = new Date().toISOString();

  const hasCustomRange = isIsoDay(sp.from) && isIsoDay(sp.to);

  // Latest window is only meaningful when we're not explicitly selecting a range.
  const latestIso = hasCustomRange
    ? null
    : (await getLatestAnalysedAt().catch(() => null)) ?? null;

  // Use calendar-day boundaries so the default 7-day window doesn't miss the first day.
  // Default is 7 full days (inclusive) anchored on the current UTC day.
  const nowSince = hasCustomRange
    ? startOfUtcDayFromYmd(sp.from!)
    : isoDaysBefore(startOfUtcDayIso(nowIso), 6);

  const nowUntil = hasCustomRange ? endOfUtcDayFromYmd(sp.to!) : nowIso;

  const latestSince = latestIso
    ? isoDaysBefore(startOfUtcDayIso(latestIso), 6)
    : null;

  const latestUntil = latestIso;

  const [itemsNow, itemsLatest, nvd] = await Promise.all([
    getTimelineItemsSince(nowSince, 2000, nowUntil).catch(() => []),
    latestSince && latestUntil
      ? getTimelineItemsSince(latestSince, 2000, latestUntil).catch(() => [])
      : Promise.resolve([]),
    // CVEs can be high volume; allow pagination to pull enough rows.
    getNvdTimelineItemsSince(nowSince, 15000, nowUntil).catch(() => []),
  ]);

  const latestWindow =
    latestIso && latestSince && latestUntil
      ? { since: latestSince, until: latestUntil, items: itemsLatest }
      : null;

  return (
    <TimelineClient
      now={{ since: nowSince, until: nowUntil, items: itemsNow }}
      latest={latestWindow}
      nvd={{ since: nowSince, until: nowUntil, items: nvd }}
      initialRange={hasCustomRange ? { from: sp.from!, to: sp.to! } : null}
    />
  );
}
