type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

export type NvdExtract = {
  descriptionEn?: string;
  cwes: string[];
  cpes: { vendor: string; product: string }[];
  references: { url: string; source?: string; tags?: string[] }[];
};

function safeToArray(v: any): any[] {
  return Array.isArray(v) ? v : v ? [v] : [];
}

function safeToString(v: any): string | undefined {
  return typeof v === "string" ? v : v == null ? undefined : String(v);
}

function uniqPush<T>(arr: T[], item: T, keyFn: (x: T) => string) {
  const k = keyFn(item);
  if (!arr.some((x) => keyFn(x) === k)) arr.push(item);
}

/**
 * Extracts a small set of human-friendly fields from NVD JSON.
 *
 * Supports both common NVD 2.0-ish shapes:
 * - { cve: { descriptions, weaknesses, references }, configurations: [...] }
 * - { descriptions, weaknesses, references, configurations } (less common)
 */
export function extractNvd(json: JsonValue): NvdExtract {
  const out: NvdExtract = { cwes: [], cpes: [], references: [] };
  if (!json || typeof json !== "object") return out;

  const j: any = json;

  // Description
  const descriptions = safeToArray(j?.cve?.descriptions ?? j?.descriptions);
  const en = descriptions.find(
    (d) => d?.lang === "en" && typeof d?.value === "string" && d.value.trim()
  );
  if (en?.value) out.descriptionEn = String(en.value);

  // Weaknesses / CWEs
  const weaknesses = safeToArray(j?.cve?.weaknesses ?? j?.weaknesses);
  const cweSet = new Set<string>();
  for (const w of weaknesses) {
    for (const d of safeToArray(w?.description)) {
      const val = safeToString(d?.value);
      if (val && val.trim()) cweSet.add(val.trim());
    }
  }
  out.cwes = Array.from(cweSet).slice(0, 12);

  // References
  const refs = safeToArray(j?.cve?.references ?? j?.references);
  for (const r of refs) {
    const url = safeToString(r?.url);
    if (!url) continue;
    const source = safeToString(r?.source);
    const tags = safeToArray(r?.tags).map((t) => safeToString(t)).filter(Boolean) as string[];
    uniqPush(out.references, { url, source, tags: tags.length ? tags : undefined }, (x) => x.url);
    if (out.references.length >= 40) break;
  }

  // CPEs
  const configs = safeToArray(j?.configurations ?? j?.cve?.configurations);
  const nodes = configs.flatMap((c) => safeToArray(c?.nodes));
  const cpeMatches = nodes.flatMap((n) => safeToArray(n?.cpeMatch));
  const criteria = cpeMatches.map((m) => safeToString(m?.criteria)).filter(Boolean) as string[];

  const cpeSet = new Set<string>();
  for (const c of criteria) {
    const parts = String(c).split(":");
    // cpe:2.3:a:vendor:product:version:...
    if (parts.length >= 5 && parts[0] === "cpe" && parts[1] === "2.3") {
      const vendor = parts[3];
      const product = parts[4];
      if (vendor && product) {
        const key = `${vendor}:${product}`;
        if (!cpeSet.has(key)) {
          cpeSet.add(key);
          out.cpes.push({ vendor, product });
          if (out.cpes.length >= 18) break;
        }
      }
    }
  }

  return out;
}
