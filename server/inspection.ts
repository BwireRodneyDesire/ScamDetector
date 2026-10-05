import dns from "node:dns/promises";
import net from "node:net";

export type SignalSeverity = "low" | "medium" | "high";
export type SignalCategory = "URL structure" | "Page signals" | "HTTPS / TLS";

export type InspectionSignal = {
  id: string;
  category: SignalCategory;
  label: string;
  severity: SignalSeverity;
  status: "passed" | "info" | "warning" | "not_checked";
  evidence: string;
  why: string;
};

export type InspectionResult = {
  url: string;
  verdict: "Low risk" | "Review" | "High risk";
  classification: "phishing" | "legitimate";
  confidence: number;
  riskScore: number;
  headline: string;
  summary: string;
  reasons: string[];
  signals: InspectionSignal[];
  features: InspectionSignal[];
  checkedAt: string;
  fetchStatus: number | null;
  allowlistedEntity: string | null;
  communityReports?: { reportCount: number; userCount: number; categories: Array<{ category: string; count: number }> };
};

const MAX_HTML_BYTES = 1_500_000;
const REQUEST_TIMEOUT_MS = 8_000;
const USER_AGENT = "PhishGuard/1.1 Makerere research prototype";

const ALLOWLIST: Array<{ entity: string; domains: string[] }> = [
  { entity: "WhatsApp", domains: ["whatsapp.com", "whatsapp.net"] },
  { entity: "Google", domains: ["google.com", "googleusercontent.com", "gstatic.com"] },
  { entity: "Microsoft", domains: ["microsoft.com", "live.com", "office.com", "microsoftonline.com"] },
  { entity: "GitHub", domains: ["github.com", "githubusercontent.com", "githubassets.com"] },
  { entity: "Wikipedia", domains: ["wikipedia.org", "wikimedia.org"] },
];

function countMatches(text: string, pattern: RegExp): number { return Array.from(text.matchAll(pattern)).length; }

function isPrivateIpv4(value: string): boolean {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) || (parts[0] === 169 && parts[1] === 254);
}

function isPrivateIpv6(value: string): boolean {
  const normalized = value.toLowerCase();
  return normalized === "::1" || normalized === "::" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:");
}

async function isBlockedHost(hostname: string): Promise<boolean> {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) return true;
  const ipType = net.isIP(host);
  if (ipType === 4) return isPrivateIpv4(host);
  if (ipType === 6) return isPrivateIpv6(host);
  try {
    const addresses = await dns.lookup(host, { all: true });
    return addresses.some(({ address }) => isPrivateIpv4(address) || isPrivateIpv6(address));
  } catch { return false; }
}

function normalizeUrl(rawUrl: string): URL {
  const value = rawUrl.trim();
  if (!value) throw new Error("Enter a URL to scan.");
  if (/\s/.test(value)) throw new Error("The URL cannot contain spaces.");
  let url: URL;
  try { url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`); }
  catch { throw new Error("That does not look like a valid website address."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS URLs are supported.");
  if (!url.hostname) throw new Error("Enter a complete website address.");
  return url;
}

function getPageText(html: string): string {
  return html.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function hostFeatureStatus(value: number, watchAt: number, riskAt: number): SignalSeverity {
  return value >= riskAt ? "high" : value >= watchAt ? "medium" : "low";
}

function isRelatedDomain(host: string, domain: string): boolean { return host === domain || host.endsWith(`.${domain}`); }

function allowlistedEntity(host: string): string | null {
  return ALLOWLIST.find((entry) => entry.domains.some((domain) => isRelatedDomain(host, domain)))?.entity ?? null;
}

function levenshtein(left: string, right: string): number {
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i += 1) {
    let previous = row[0]; row[0] = i;
    for (let j = 1; j <= right.length; j += 1) {
      const current = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (left[i - 1] === right[j - 1] ? 0 : 1));
      previous = current;
    }
  }
  return row[right.length];
}

function lookalikeBrand(host: string): string | null {
  const root = host.split(".").slice(-2, -1)[0]?.toLowerCase() ?? host;
  const brands = ["whatsapp", "google", "microsoft", "github", "wikipedia", "airtel", "mtn"];
  return brands.find((brand) => root !== brand && root.length >= 5 && levenshtein(root, brand) <= 2) ?? null;
}

function severityStatus(severity: SignalSeverity, passed = false): "passed" | "info" | "warning" {
  return passed ? "passed" : severity === "low" ? "info" : "warning";
}

function extractLinkReferences(html: string): string[] {
  const references: string[] = [];
  const anchorPattern = /<a\b[^>]*?\b(?:href|data-href|data-url|data-link)\s*=\s*["']([^"']+)["'][^>]*>/gi;
  for (const match of Array.from(html.matchAll(anchorPattern))) {
    if (match[1]) references.push(match[1].trim());
  }

  // Many client-rendered pages keep destination URLs in inline scripts before
  // creating their anchors. Only count URLs attached to navigation-like keys or
  // calls so image, stylesheet, analytics, and API assets are not misclassified.
  const scripts = html.match(/<script\b[^>]*>[\s\S]*?<\/script>/gi) ?? [];
  for (const script of scripts) {
    const body = script.replace(/^<script\b[^>]*>/i, "").replace(/<\/script>$/i, "");
    const navigationPattern = /(?:href|location(?:\.href)?|window\.open|navigate|router\.(?:push|replace)|(?:^|[,{\s])to)\s*(?:[:=(])\s*["']((?:https?:)?\/\/[^\s"'<>`\\)]+)["']/gi;
    for (const match of Array.from(body.matchAll(navigationPattern))) {
      if (match[1]) references.push(match[1].replace(/[),.;]+$/, ""));
    }
  }
  return references;
}

export async function inspectUrl(rawUrl: string): Promise<InspectionResult> {
  const url = normalizeUrl(rawUrl);
  if (await isBlockedHost(url.hostname)) throw new Error("Private or local network addresses cannot be scanned.");

  let html = "";
  let fetchStatus: number | null = null;
  let fetchFailed = false;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const response = await fetch(url, { headers: { "user-agent": USER_AGENT, accept: "text/html,application/xhtml+xml" }, redirect: "follow", signal: controller.signal });
    clearTimeout(timer);
    fetchStatus = response.status;
    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("text/html") || contentType === "") html = (await response.text()).slice(0, MAX_HTML_BYTES);
  } catch { fetchFailed = true; }

  const host = url.hostname.toLowerCase();
  const labels = host.split(".").filter(Boolean);
  const subdomainCount = Math.max(0, labels.length - 2);
  const hasIpAddress = net.isIP(host) > 0;
  const text = getPageText(html).toLowerCase();
  const forms = countMatches(html, /<form\b/gi);
  const iframes = countMatches(html, /<iframe\b/gi);
  const links = extractLinkReferences(html);
  const externalLinks = links.filter((href) => { try { return new URL(href, url).hostname !== host; } catch { return false; } }).length;
  const internalLinks = Math.max(0, links.length - externalLinks);
  const faviconPresent = /<link\b[^>]*rel\s*=\s*["'][^"']*icon[^"']*["']/i.test(html);
  const faviconUrl = html.match(/<link\b[^>]*rel\s*=\s*["'][^"']*icon[^"']*["'][^>]*href\s*=\s*["']([^"']+)/i)?.[1];
  const faviconMismatch = Boolean(faviconUrl && (() => { try { return new URL(faviconUrl, url).hostname !== host; } catch { return false; } })());
  const hiddenElements = countMatches(html, /(?:display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*["']hidden["']|\bhidden\b)/gi);
  const sensitiveTerms = ["verify", "login", "signin", "password", "mobile money", "loan", "investment", "urgent", "job offer", "account suspended"];
  const matchedTerms = sensitiveTerms.filter((term) => text.includes(term));
  const formActionHosts = Array.from(html.matchAll(/<form\b[^>]*action\s*=\s*["']([^"']+)["'][^>]*>/gi)).map((match) => { try { return new URL(match[1], url).hostname; } catch { return host; } });
  const crossDomainForm = formActionHosts.some((actionHost) => actionHost !== host);
  const isPunycode = host.includes("xn--");
  const lookalike = lookalikeBrand(host);
  const entity = allowlistedEntity(host);
  const hostRiskTerms = ["login", "verify", "secure", "account", "update", "support", "wallet", "auth"];
  const hostRiskMatches = hostRiskTerms.filter((term) => host.includes(term));
  const hostHasManyHyphens = (host.match(/-/g) ?? []).length >= 3;
  const urlLength = url.href.length;

  const signals: InspectionSignal[] = [];
  const add = (signal: InspectionSignal) => signals.push(signal);
  add({ id: "https", category: "HTTPS / TLS", label: "HTTPS connection", severity: url.protocol === "https:" && !fetchFailed ? "low" : "high", status: url.protocol === "https:" && !fetchFailed ? "passed" : "warning", evidence: url.protocol === "https:" ? (fetchFailed ? "HTTPS requested, but the page did not respond reliably" : "HTTPS connection established") : "HTTP connection", why: "HTTPS helps protect data in transit, but it does not prove that a site is legitimate." });
  add({ id: "url-length", category: "URL structure", label: "URL length", severity: hostFeatureStatus(urlLength, 55, 90), status: severityStatus(hostFeatureStatus(urlLength, 55, 90), urlLength < 55), evidence: `${urlLength} characters`, why: "Very long addresses can hide the destination or carry deceptive tracking paths." });
  add({ id: "subdomains", category: "URL structure", label: "Nested subdomains", severity: hostFeatureStatus(subdomainCount, 2, 4), status: severityStatus(hostFeatureStatus(subdomainCount, 2, 4), subdomainCount < 2), evidence: `${subdomainCount} subdomain${subdomainCount === 1 ? "" : "s"} detected`, why: "Attackers sometimes place a trusted-looking name deep inside a long host name." });
  add({ id: "ip-host", category: "URL structure", label: "IP address host", severity: hasIpAddress ? "high" : "low", status: hasIpAddress ? "warning" : "passed", evidence: hasIpAddress ? "The host is an IP address" : "A named domain is used", why: "Legitimate services usually use a stable domain name; IP-only links are harder to verify." });
  add({ id: "at-symbol", category: "URL structure", label: "@ symbol in address", severity: url.href.includes("@") ? "high" : "low", status: url.href.includes("@") ? "warning" : "passed", evidence: url.href.includes("@") ? "An @ symbol is present" : "No @ symbol detected", why: "In URLs, text before @ can disguise the real destination host." });
  add({ id: "punycode", category: "URL structure", label: "Internationalized host encoding", severity: isPunycode ? "high" : "low", status: isPunycode ? "warning" : "passed", evidence: isPunycode ? "Punycode (xn--) detected" : "No punycode detected", why: "Lookalike characters can make a deceptive domain resemble a familiar brand." });
  add({ id: "lookalike", category: "URL structure", label: "Brand lookalike check", severity: lookalike && !entity ? "high" : "low", status: lookalike && !entity ? "warning" : "passed", evidence: lookalike && !entity ? `The host resembles ${lookalike}` : entity ? `${entity} related domain recognized` : "No obvious brand lookalike detected", why: "Small spelling changes in a brand name are a common phishing technique." });
  add({ id: "host-language", category: "URL structure", label: "Login-style host language", severity: hostRiskMatches.length >= 2 && !entity ? "high" : hostRiskMatches.length ? "medium" : "low", status: hostRiskMatches.length >= 2 && !entity ? "warning" : hostRiskMatches.length ? "info" : "passed", evidence: hostRiskMatches.length ? `${hostRiskMatches.join(", ")} appears in the host` : "No login-style terms in the host", why: "Words such as login, verify, and account in a new or unrelated host can imitate a trusted service." });
  add({ id: "hyphenated-host", category: "URL structure", label: "Hyphenated host", severity: hostHasManyHyphens && !entity ? "medium" : "low", status: hostHasManyHyphens && !entity ? "info" : "passed", evidence: hostHasManyHyphens ? "Three or more hyphens appear in the host" : "No excessive hyphen pattern", why: "Long hyphenated hosts are sometimes used to pack brand and login words into a deceptive address." });
  add({ id: "forms", category: "Page signals", label: "Forms and sensitive language", severity: fetchFailed ? "low" : forms > 0 && matchedTerms.length > 0 ? "high" : forms > 2 ? "medium" : "low", status: fetchFailed ? "not_checked" : severityStatus(forms > 0 && matchedTerms.length > 0 ? "high" : forms > 2 ? "medium" : "low", forms === 0 || matchedTerms.length === 0), evidence: fetchFailed ? "Not checked: page could not be fetched" : `${forms} form${forms === 1 ? "" : "s"}; ${matchedTerms.length ? `${matchedTerms.slice(0, 3).join(", ")} language found` : "no sensitive language found"}`, why: "A password or payment form combined with urgency or verification language deserves close review." });
  add({ id: "cross-form", category: "Page signals", label: "Form destination", severity: fetchFailed ? "low" : crossDomainForm ? "high" : "low", status: fetchFailed ? "not_checked" : crossDomainForm ? "warning" : "passed", evidence: fetchFailed ? "Not checked: page could not be fetched" : crossDomainForm ? "A form posts to another domain" : "Forms stay on the scanned host or no form action was found", why: "Sending credentials to a different domain is a strong warning sign." });
  add({ id: "external-links", category: "Page signals", label: "External links", severity: fetchFailed ? "low" : externalLinks > internalLinks && externalLinks > 3 ? "medium" : "low", status: fetchFailed ? "not_checked" : severityStatus(externalLinks > internalLinks && externalLinks > 3 ? "medium" : "low", externalLinks <= internalLinks || externalLinks <= 3), evidence: fetchFailed ? "Not checked: page could not be fetched" : `${externalLinks} external and ${internalLinks} internal link${internalLinks === 1 ? "" : "s"}`, why: "A page that mainly points away from its own host can be a temporary lure, but this is only a weak signal." });
  add({ id: "hidden", category: "Page signals", label: "Hidden elements", severity: fetchFailed ? "low" : hiddenElements >= 8 ? "medium" : "low", status: fetchFailed ? "not_checked" : severityStatus(hiddenElements >= 8 ? "medium" : "low", hiddenElements < 8), evidence: fetchFailed ? "Not checked: page could not be fetched" : `${hiddenElements} hidden element${hiddenElements === 1 ? "" : "s"} found`, why: "Hidden content can be used for obfuscation, although modern legitimate pages also use it for accessibility and layout." });
  add({ id: "favicon", category: "Page signals", label: "Favicon origin", severity: faviconMismatch ? "low" : "low", status: fetchFailed ? "not_checked" : faviconMismatch ? "info" : "passed", evidence: fetchFailed ? "Not checked: page could not be fetched" : faviconMismatch ? "Favicon appears to come from another domain" : faviconPresent ? "Favicon matches the scanned host" : "No favicon detected", why: "A different favicon host is a weak clue and should never decide the verdict alone." });
  add({ id: "fetch", category: "HTTPS / TLS", label: "Page response", severity: fetchFailed ? "medium" : "low", status: fetchFailed ? "warning" : "passed", evidence: fetchFailed ? "Timed out or could not be fetched" : `Fetched successfully${fetchStatus ? ` (HTTP ${fetchStatus})` : ""}`, why: "A failed fetch reduces confidence because page signals could not be checked." });

  let riskScore = 0;
  const reasons: string[] = [];
  const strongSignals = [hasIpAddress, Boolean(url.href.includes("@")), isPunycode, Boolean(lookalike && !entity), crossDomainForm, url.protocol !== "https:"];
  riskScore += hasIpAddress ? 30 : 0;
  riskScore += url.href.includes("@") ? 24 : 0;
  riskScore += isPunycode ? 24 : 0;
  riskScore += lookalike && !entity ? 30 : 0;
  riskScore += hostRiskMatches.length >= 2 && !entity ? 18 : hostRiskMatches.length && !entity ? 6 : 0;
  riskScore += hostHasManyHyphens && !entity ? 12 : 0;
  riskScore += crossDomainForm ? 28 : 0;
  riskScore += url.protocol !== "https:" ? 14 : 0;
  riskScore += subdomainCount >= 4 ? 13 : subdomainCount >= 2 ? 4 : 0;
  riskScore += forms > 0 && matchedTerms.length > 0 ? 15 : 0;
  riskScore += externalLinks > internalLinks && externalLinks > 3 ? 4 : 0;
  riskScore += hiddenElements >= 8 ? 3 : 0;
  riskScore += faviconMismatch ? 2 : 0;
  riskScore += fetchFailed ? 4 : 0;

  if (entity && strongSignals.filter(Boolean).length === 0) {
    riskScore = Math.min(riskScore, 8);
    reasons.push(`${entity} related domain recognized; weak page signals are shown as informational notes.`);
  }
  riskScore = Math.min(100, riskScore);
  signals.filter((signal) => signal.status === "warning").forEach((signal) => reasons.push(`${signal.label}: ${signal.evidence}.`));
  if (reasons.length === 0) reasons.push("The address and page response show no strong phishing pattern.");

  const verdict = riskScore >= 45 ? "High risk" : riskScore >= 25 ? "Review" : "Low risk";
  const classification = verdict === "High risk" ? "phishing" : "legitimate";
  const confidence = Math.min(0.98, Math.max(0.52, verdict === "High risk" ? 0.56 + riskScore / 220 : 0.62 + (100 - riskScore) / 280));
  const headline = verdict === "High risk" ? "Treat this website as high risk" : verdict === "Review" ? "Review this website carefully" : "No strong phishing signals found";
  const summary = fetchFailed ? "The address was analyzed, but the page did not respond reliably, so confidence is lower." : `The rule-based scan evaluated ${signals.length} signals across URL structure, page signals, and HTTPS / TLS.`;

  return {
    url: url.href, verdict, classification, confidence: Number(confidence.toFixed(3)), riskScore, headline, summary,
    reasons: reasons.slice(0, 5), signals, features: signals, checkedAt: new Date().toISOString(), fetchStatus, allowlistedEntity: entity,
  };
}
