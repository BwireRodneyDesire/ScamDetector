import { invokeLLM } from "./_core/llm";
import type { InspectionResult } from "./inspection";

export type ExplanationResult = { text: string; source: "ai" | "fallback" };

const SYSTEM_PROMPT =
  "You are a security assistant explaining website scan results to a non-technical user. Using ONLY the JSON findings, write exactly 2 or 3 short plain-language sentences under 60 words. Mention only the 1 or 2 most important findings by name. Community reports are unverified user opinions, not proof. If the JSON says the site could not be reached reliably, use that exact idea and do not call it a high-severity HTTPS problem. Say that listed patterns can also occur on legitimate sites when appropriate. End with one clear recommended action. Do not use markdown, asterisks, certainty claims, or outside facts.";

function fallbackExplanation(result: InspectionResult): ExplanationResult {
  const notable = result.signals
    .filter(
      signal =>
        signal.id !== "https" &&
        signal.status !== "not_checked" &&
        signal.severity !== "low"
    )
    .slice(0, 2);
  const details = notable.length
    ? notable
        .map(signal => `${signal.label} (${signal.evidence})`)
        .join(" and ")
    : "no medium or high severity findings";
  const reachability =
    result.fetchStatus === null
      ? "The site could not be reached reliably, so page-based checks were not available."
      : "The checked signals look broadly typical of a legitimate site.";
  if (result.verdict === "High risk")
    return {
      source: "fallback",
      text: `${reachability} The most important findings are ${details}; these patterns can also occur on legitimate sites, so this is not certain. Do not enter sensitive information and verify the address through an official source.`,
    };
  if (result.verdict === "Review")
    return {
      source: "fallback",
      text: `${reachability} The most important findings are ${details}; they deserve review but do not prove phishing. Check the domain carefully and avoid sharing sensitive information until you confirm it independently.`,
    };
  return {
    source: "fallback",
    text: `${reachability} There is no strong phishing pattern in the checks that ran, but this is not a guarantee of safety. Verify the destination before sharing sensitive information.`,
  };
}

export async function explainInspection(
  result: InspectionResult
): Promise<ExplanationResult> {
  const pageOnlyIds = new Set([
    "forms",
    "cross-form",
    "external-links",
    "hidden",
    "favicon",
  ]);
  const structuredFindings = {
    url: result.url,
    verdict: result.verdict,
    score: result.riskScore,
    communityReports: result.communityReports ?? {
      reportCount: 0,
      userCount: 0,
      categories: [],
    },
    signals: result.signals.map(
      ({ id, category, label, severity, status, evidence }) =>
        result.fetchStatus === null && pageOnlyIds.has(id)
          ? {
              category,
              label,
              severity: "not_checked",
              status: "not_checked",
              evidence: "The site could not be reached reliably",
            }
          : id === "https" && result.fetchStatus === null
            ? {
                category,
                label,
                severity: "not_checked",
                status: "not_checked",
                evidence: "The site could not be reached reliably",
              }
            : { category, label, severity, status, evidence }
    ),
  };
  try {
    const response = await invokeLLM({
      model: "claude-haiku-4-5",
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: JSON.stringify(structuredFindings) },
      ],
      maxTokens: 240,
    });
    const content = response.choices[0]?.message?.content;
    const text =
      typeof content === "string" ? content.trim().replace(/\*+/g, "") : "";
    const words = text.split(/\s+/).filter(Boolean);
    if (
      !text ||
      words.length > 59 ||
      response.choices[0]?.finish_reason === "length"
    )
      return fallbackExplanation(result);
    return { source: "ai", text };
  } catch {
    return fallbackExplanation(result);
  }
}
