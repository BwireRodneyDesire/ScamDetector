const URL_PATTERN =
  /(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;

function cleanCandidate(candidate: string): string {
  return candidate.replace(/[),.;!?]+$/g, "");
}

export function extractUrls(message: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();

  for (const match of Array.from(message.matchAll(URL_PATTERN))) {
    const candidate = cleanCandidate(match[0]);
    const normalized = candidate.toLowerCase().startsWith("www.")
      ? `https://${candidate}`
      : candidate;
    try {
      const url = new URL(normalized);
      if (!["http:", "https:"].includes(url.protocol)) continue;
      const value = url.href;
      if (!seen.has(value)) {
        seen.add(value);
        found.push(value);
      }
    } catch {
      // Ignore text that resembles a URL but cannot be parsed safely.
    }
  }

  return found;
}
