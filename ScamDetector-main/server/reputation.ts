import dns from "node:dns/promises";
import net from "node:net";

export type ReputationStatus = "checked" | "not_checked";
export type ReputationSignal = {
  id: string;
  label: string;
  severity: "low" | "medium" | "high";
  status: "passed" | "info" | "warning" | "not_checked";
  evidence: string;
  why: string;
};
export type ReputationData = {
  domain: string;
  registeredDomain: string;
  domainAgeDays: number | null;
  registrationDate: string | null;
  expiryDate: string | null;
  registrar: string | null;
  popularityRank: number | null;
  hostingIp: string | null;
  hostingCountry: string | null;
  hostingProvider: string | null;
  redirectChain: string[];
  redirectCrossesDomain: boolean;
  finalDomain: string | null;
  finalHasLoginForm: boolean | null;
  safeBrowsingThreats: string[];
  urlhausThreats: string[];
  signals: ReputationSignal[];
  status: ReputationStatus;
};

type CacheEntry<T> = { value: T; expiresAt: number };
const cache = new Map<string, CacheEntry<unknown>>();
const CACHE_MS = 24 * 60 * 60 * 1000;
const LOOKUP_TIMEOUT_MS = 4_500;
const TOTAL_TIMEOUT_MS = 7_000;
const UA = "PhishGuard/1.2 Makerere research prototype";
const SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY ?? "";

function cached<T>(key: string): T | undefined {
  const item = cache.get(key) as CacheEntry<T> | undefined;
  if (!item) return undefined;
  if (item.expiresAt < Date.now()) {
    cache.delete(key);
    return undefined;
  }
  return item.value;
}
function put<T>(key: string, value: T) {
  cache.set(key, { value, expiresAt: Date.now() + CACHE_MS });
  return value;
}
async function withTimeout<T>(
  promise: Promise<T>,
  ms = LOOKUP_TIMEOUT_MS
): Promise<T> {
  return await Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), ms)
    ),
  ]);
}
function registeredDomain(host: string) {
  const labels = host
    .toLowerCase()
    .replace(/^www\./, "")
    .split(".")
    .filter(Boolean);
  return labels.length >= 2 ? labels.slice(-2).join(".") : host.toLowerCase();
}
function privateIp(value: string) {
  const type = net.isIP(value);
  if (type === 4) {
    const p = value.split(".").map(Number);
    return (
      p[0] === 10 ||
      p[0] === 127 ||
      p[0] === 0 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 169 && p[1] === 254)
    );
  }
  if (type === 6) {
    const v = value.toLowerCase();
    return (
      v === "::" ||
      v === "::1" ||
      v.startsWith("fc") ||
      v.startsWith("fd") ||
      v.startsWith("fe80:")
    );
  }
  return false;
}
async function resolvePublicIp(host: string) {
  if (net.isIP(host)) return privateIp(host) ? null : host;
  const addresses = await dns.lookup(host, { all: true });
  return addresses.find(({ address }) => !privateIp(address))?.address ?? null;
}
async function jsonFetch(url: string, init?: RequestInit) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      ...init,
      headers: {
        "user-agent": UA,
        accept: "application/json,text/plain,*/*",
        ...(init?.headers ?? {}),
      },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return (await response.json()) as any;
  } finally {
    clearTimeout(timer);
  }
}
async function rdap(domain: string) {
  const key = `rdap:${domain}`;
  const prior = cached<any>(key);
  if (prior) return prior;
  const data = await jsonFetch(
    `https://rdap.org/domain/${encodeURIComponent(domain)}`
  );
  const events = Array.isArray(data.events) ? data.events : [];
  const registration =
    events.find((e: any) =>
      ["registration", "registered"].includes(e.eventAction)
    )?.eventDate ?? null;
  const expiry =
    events.find((e: any) => ["expiration", "expiry"].includes(e.eventAction))
      ?.eventDate ?? null;
  const registrar = Array.isArray(data.entities)
    ? (data.entities
        .find((e: any) => e.roles?.includes("registrar"))
        ?.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3] ?? null)
    : null;
  return put(key, { registration, expiry, registrar });
}
async function tranco(domain: string) {
  const key = `tranco:${domain}`;
  const prior = cached<number | null>(key);
  if (prior !== undefined) return prior;
  const data = await jsonFetch(
    `https://tranco-list.eu/api/ranks/domain/${encodeURIComponent(domain)}`
  );
  const ranks = Array.isArray(data.ranks)
    ? data.ranks
        .map((item: any) => Number(item.rank))
        .filter((rank: number) => Number.isFinite(rank))
    : [];
  const rank = ranks.length ? Math.min(...ranks) : null;
  return put(key, rank !== null && rank <= 100000 ? rank : null);
}
async function blocklists(url: string) {
  const domain = new URL(url).hostname.toLowerCase();
  const key = `blocklists:${domain}`;
  const prior = cached<any>(key);
  if (prior) return prior;
  const safe: string[] = [];
  if (SAFE_BROWSING_KEY) {
    try {
      const data = await jsonFetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(SAFE_BROWSING_KEY)}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "phishguard", clientVersion: "1.2" },
            threatInfo: {
              threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
              ],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url }],
            },
          }),
        }
      );
      for (const match of data.matches ?? [])
        safe.push(`Google Safe Browsing: ${match.threatType}`);
    } catch {
      /* graceful */
    }
  }
  const urlhaus: string[] = [];
  try {
    const data = await jsonFetch(`https://urlhaus-api.abuse.ch/v1/host/`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ host: domain }).toString(),
    });
    for (const item of data.urls ?? [])
      urlhaus.push(`URLhaus: ${item.threat ?? "listed URL"}`);
  } catch {
    /* graceful */
  }
  return put(key, {
    safe,
    urlhaus,
    safeBrowsingChecked: Boolean(SAFE_BROWSING_KEY),
    urlhausChecked: true,
  });
}
async function hosting(host: string) {
  const key = `hosting:${host}`;
  const prior = cached<any>(key);
  if (prior) return prior;
  const ip = await resolvePublicIp(host);
  if (!ip) return put(key, { ip: null, country: null, provider: null });
  try {
    const data = await jsonFetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
    return put(key, {
      ip,
      country: data.country ?? null,
      provider: data.connection?.org ?? data.connection?.isp ?? null,
    });
  } catch {
    return put(key, { ip, country: null, provider: null });
  }
}
async function redirects(url: URL) {
  const key = `redirects:${url.href}`;
  const prior = cached<any>(key);
  if (prior) return prior;
  const chain = [url.href];
  let current = url;
  let finalHasLoginForm: boolean | null = null;
  let checked = false;
  for (let hop = 0; hop < 5; hop += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000);
    try {
      const response = await fetch(current, {
        redirect: "manual",
        headers: { "user-agent": UA, accept: "text/html,*/*" },
        signal: controller.signal,
      });
      checked = true;
      const location = response.headers.get("location");
      if (!location || ![301, 302, 303, 307, 308].includes(response.status)) {
        if (response.headers.get("content-type")?.includes("text/html"))
          finalHasLoginForm =
            /<form\b[\s\S]{0,2000}(?:login|password|signin)/i.test(
              (await response.text()).slice(0, 250_000)
            );
        break;
      }
      const next = new URL(location, current);
      if ((await resolvePublicIp(next.hostname)) === null) break;
      current = next;
      chain.push(current.href);
    } catch {
      break;
    } finally {
      clearTimeout(timer);
    }
  }
  const domains = chain.map(value => registeredDomain(new URL(value).hostname));
  return put(key, {
    chain,
    cross: new Set(domains).size > 1,
    finalDomain: domains.at(-1) ?? null,
    finalHasLoginForm,
    checked,
  });
}

function ageDays(date: string | null) {
  return date
    ? Math.max(0, Math.floor((Date.now() - Date.parse(date)) / 86_400_000))
    : null;
}

export async function collectReputation(url: URL): Promise<ReputationData> {
  const domain = url.hostname.toLowerCase();
  const root = registeredDomain(domain);
  const fallback = {
    domain,
    registeredDomain: root,
    domainAgeDays: null,
    registrationDate: null,
    expiryDate: null,
    registrar: null,
    popularityRank: null,
    hostingIp: null,
    hostingCountry: null,
    hostingProvider: null,
    redirectChain: [url.href],
    redirectCrossesDomain: false,
    finalDomain: root,
    finalHasLoginForm: null,
    safeBrowsingThreats: [],
    urlhausThreats: [],
    signals: [
      ["domain-age", "Domain age"],
      ["blocklists", "Blocklists"],
      ["popularity", "Popularity rank"],
      ["hosting", "Hosting location"],
      ["redirects", "Redirect chain"],
    ].map(([id, label]) => ({
      id,
      label,
      severity: "low" as const,
      status: "not_checked" as const,
      evidence: "Not checked: reputation service unavailable",
      why: "This optional reputation check could not be completed.",
    })),
    status: "not_checked" as ReputationStatus,
  };
  try {
    const results = await withTimeout(
      Promise.allSettled([
        rdap(root),
        tranco(root),
        blocklists(url.href),
        hosting(domain),
        redirects(url),
      ]),
      TOTAL_TIMEOUT_MS
    );
    const [
      rdapResult,
      trancoResult,
      blockResult,
      hostingResult,
      redirectResult,
    ] = results;
    const rd = rdapResult.status === "fulfilled" ? rdapResult.value : null;
    const rank =
      trancoResult.status === "fulfilled" ? trancoResult.value : null;
    const bl = blockResult.status === "fulfilled" ? blockResult.value : null;
    const hp =
      hostingResult.status === "fulfilled" ? hostingResult.value : null;
    const red =
      redirectResult.status === "fulfilled" ? redirectResult.value : null;
    const days = ageDays(rd?.registration ?? null);
    const signals: ReputationSignal[] = [];
    signals.push({
      id: "domain-age",
      label: "Domain age",
      severity:
        days !== null && days < 30
          ? "high"
          : days !== null && days < 730
            ? "medium"
            : "low",
      status:
        days === null
          ? "not_checked"
          : days < 30
            ? "warning"
            : days < 730
              ? "warning"
              : "passed",
      evidence:
        days === null
          ? "Not checked: registration date unavailable"
          : `${days} days old${rd?.registration ? `; registered ${rd.registration.slice(0, 10)}` : ""}`,
      why: "Very new domains have had less time to build a verifiable reputation, although age alone does not prove abuse.",
    });
    signals.push({
      id: "blocklists",
      label: "Blocklists",
      severity: bl && (bl.safe.length || bl.urlhaus.length) ? "high" : "low",
      status:
        !bl || bl.safe.length || bl.urlhaus.length
          ? bl && (bl.safe.length || bl.urlhaus.length)
            ? "warning"
            : "not_checked"
          : !bl.safeBrowsingChecked
            ? "not_checked"
            : "passed",
      evidence: !bl
        ? "Not checked: blocklist services unavailable"
        : bl.safe.length || bl.urlhaus.length
          ? [...bl.safe, ...bl.urlhaus].join("; ")
          : bl.safeBrowsingChecked
            ? "Not listed by Google Safe Browsing or URLhaus"
            : "URLhaus did not list this host; Google Safe Browsing key not configured",
      why: "A blocklist match is a strong warning, but a clean result is not a guarantee of safety.",
    });
    signals.push({
      id: "popularity",
      label: "Popularity rank",
      severity: "low",
      status: rank ? "info" : "not_checked",
      evidence: rank
        ? `Tranco rank #${rank}`
        : "Not checked: Tranco list unavailable or domain not ranked",
      why: "Popularity can provide context, but obscure legitimate sites are not automatically suspicious.",
    });
    signals.push({
      id: "hosting",
      label: "Hosting location",
      severity: "low",
      status: hp?.country ? "info" : "not_checked",
      evidence: hp?.country
        ? `${hp.country}${hp.provider ? ` · ${hp.provider}` : ""}`
        : "Not checked: hosting details unavailable",
      why: "Hosting information is informational context and should not decide the verdict.",
    });
    signals.push({
      id: "redirects",
      label: "Redirect chain",
      severity: red?.cross ? "medium" : "low",
      status: red?.checked ? (red.cross ? "warning" : "info") : "not_checked",
      evidence: red
        ? `${red.chain.length - 1} redirect${red.chain.length - 1 === 1 ? "" : "s"}${red.cross ? "; crosses registered domains" : ""}`
        : "Not checked: redirect chain unavailable",
      why: "Unexpected cross-domain redirects can obscure the final destination.",
    });
    return {
      ...fallback,
      registrationDate: rd?.registration ?? null,
      expiryDate: rd?.expiry ?? null,
      registrar: rd?.registrar ?? null,
      domainAgeDays: days,
      popularityRank: rank,
      hostingIp: hp?.ip ?? null,
      hostingCountry: hp?.country ?? null,
      hostingProvider: hp?.provider ?? null,
      redirectChain: red?.chain ?? fallback.redirectChain,
      redirectCrossesDomain: Boolean(red?.cross),
      finalDomain: red?.finalDomain ?? root,
      finalHasLoginForm: red?.finalHasLoginForm ?? null,
      safeBrowsingThreats: bl?.safe ?? [],
      urlhausThreats: bl?.urlhaus ?? [],
      signals,
      status: signals.some(signal => signal.status !== "not_checked")
        ? "checked"
        : "not_checked",
    };
  } catch {
    return fallback;
  }
}
