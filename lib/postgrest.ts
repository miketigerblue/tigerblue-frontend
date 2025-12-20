import "server-only";

const BASE = process.env.NEXT_PUBLIC_POSTGREST_BASE!;
const AUTH = process.env.POSTGREST_AUTH_TOKEN;

if (!BASE) throw new Error("Missing NEXT_PUBLIC_POSTGREST_BASE");

type FetchOpts = {
  revalidate?: number;
  tags?: string[];
  headers?: Record<string, string>;
};

function buildUrl(
  path: string,
  params?: Record<string, string | number | boolean | undefined>
) {
  const u = new URL(path, BASE);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined) continue;
      u.searchParams.set(k, String(v));
    }
  }
  return u.toString();
}

export async function pgGet<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>,
  opts: FetchOpts = {}
): Promise<T> {
  const url = buildUrl(path, params);

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
      ...(AUTH ? { Authorization: `Bearer ${AUTH}` } : {}),
      ...(opts.headers ?? {}),
    },
    next: {
      revalidate: opts.revalidate ?? 30,
      tags: opts.tags,
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `PostgREST GET failed ${res.status} ${res.statusText} for ${url}\n${text}`
    );
  }

  return (await res.json()) as T;
}

export const pg = {
  eq: (col: string, value: string) => ({ [col]: `eq.${value}` }),
  in: (col: string, values: string[]) => ({ [col]: `in.(${values.join(",")})` }),
};
