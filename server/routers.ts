import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { inspectUrl, type InspectionResult } from "./inspection";
import { explainInspection } from "./explanation";
import {
  addScamReport,
  addScanHistory,
  clearScanHistory,
  countUserReportsSince,
  getCommunityReports,
  hasUserReportedHost,
  listScanHistory,
  trimScanHistory,
} from "./db";

const rateBuckets = new Map<string, { count: number; resetAt: number }>();
const SCAN_LIMIT = 20;
const SCAN_WINDOW_MS = 10 * 60 * 1000;
const REPORT_LIMIT = 5;
const REPORT_WINDOW_MS = 60 * 60 * 1000;

function requestKey(req: {
  ip?: string;
  headers: Record<string, string | string[] | undefined>;
}) {
  const forwarded = req.headers["x-forwarded-for"];
  const firstForwarded = Array.isArray(forwarded)
    ? forwarded[0]
    : forwarded?.split(",")[0];
  return firstForwarded?.trim() || req.ip || "unknown";
}
function enforceScanRateLimit(
  req: Parameters<typeof requestKey>[0],
  userId?: number
) {
  const key = userId ? `user:${userId}` : `ip:${requestKey(req)}`;
  const now = Date.now();
  const current = rateBuckets.get(key);
  if (!current || current.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + SCAN_WINDOW_MS });
    return;
  }
  if (current.count >= SCAN_LIMIT)
    throw new TRPCError({
      code: "TOO_MANY_REQUESTS",
      message:
        "Scan limit reached. Please wait a few minutes before trying again.",
    });
  current.count += 1;
}

const scanInput = z.object({ url: z.string().trim().min(1).max(2048) });
const historyInput = z.object({
  url: z.string().url().max(2048),
  verdict: z.enum(["Low risk", "Review", "High risk"]),
  riskScore: z.number().int().min(0).max(100),
  checkedAt: z.string().datetime().optional(),
});
const reportCategories = [
  "Fake login page",
  "Fake prize or giveaway",
  "Investment scam",
  "Mobile money scam",
  "Other",
] as const;
const reportInput = z.object({
  url: z.string().trim().min(1).max(2048),
  category: z.enum(reportCategories),
  description: z.string().trim().max(500).optional().default(""),
  honeypot: z.string().max(100).optional().default(""),
});

async function addCommunitySignal(
  result: InspectionResult
): Promise<InspectionResult> {
  let host: string;
  try {
    host = new URL(result.url).hostname.toLowerCase();
  } catch {
    return result;
  }
  const communityReports = await getCommunityReports(host);
  if (!communityReports.reportCount) return { ...result, communityReports };
  const top = communityReports.categories[0];
  const signal = {
    id: "community-reports",
    category: "Page signals" as const,
    label: "Community reports",
    severity: "medium" as const,
    status: "warning" as const,
    evidence: `${communityReports.userCount} ${communityReports.userCount === 1 ? "user" : "users"} reported this site as ${top?.category ?? "Other"}`,
    why: "These are unverified user opinions, not proof that a site is fraudulent. Treat repeated reports as a reason to verify the address carefully.",
  };
  return {
    ...result,
    communityReports,
    signals: [...result.signals, signal],
    features: [...result.features, signal],
    reasons: [...result.reasons, signal.evidence],
  };
}

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),
  detector: router({
    check: publicProcedure.input(scanInput).mutation(async ({ ctx, input }) => {
      enforceScanRateLimit(ctx.req, ctx.user?.id);
      const inspected = await inspectUrl(input.url);
      const result = await addCommunitySignal(inspected);
      if (ctx.user) {
        await addScanHistory({
          userId: ctx.user.id,
          url: result.url,
          verdict: result.verdict,
          riskScore: result.riskScore,
          checkedAt: new Date(result.checkedAt),
        });
        await trimScanHistory(ctx.user.id);
      }
      return result;
    }),
    explain: publicProcedure
      .input(z.object({ result: z.any() }))
      .mutation(async ({ input }) => explainInspection(input.result)),
    history: protectedProcedure.query(({ ctx }) =>
      listScanHistory(ctx.user.id)
    ),
    importHistory: protectedProcedure
      .input(z.object({ items: z.array(historyInput).max(50) }))
      .mutation(async ({ ctx, input }) => {
        for (const item of input.items)
          await addScanHistory({
            userId: ctx.user.id,
            url: item.url,
            verdict: item.verdict,
            riskScore: item.riskScore,
            checkedAt: item.checkedAt ? new Date(item.checkedAt) : new Date(),
          });
        await trimScanHistory(ctx.user.id);
        return listScanHistory(ctx.user.id);
      }),
    deleteHistory: protectedProcedure.mutation(async ({ ctx }) => {
      await clearScanHistory(ctx.user.id);
      return { success: true } as const;
    }),
    submitReport: protectedProcedure
      .input(reportInput)
      .mutation(async ({ ctx, input }) => {
        if (input.honeypot)
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "Report could not be submitted.",
          });
        let host: string;
        try {
          const parsed = new URL(
            /^[a-z][a-z\d+.-]*:\/\//i.test(input.url)
              ? input.url
              : `https://${input.url}`
          );
          if (
            !["http:", "https:"].includes(parsed.protocol) ||
            !parsed.hostname
          )
            throw new Error();
          host = parsed.hostname.toLowerCase();
        } catch {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "Enter a valid website URL.",
          });
        }
        const recent = await countUserReportsSince(
          ctx.user.id,
          new Date(Date.now() - REPORT_WINDOW_MS)
        );
        if (recent >= REPORT_LIMIT)
          throw new TRPCError({
            code: "TOO_MANY_REQUESTS",
            message: "You have reached the report limit of 5 per hour.",
          });
        if (await hasUserReportedHost(ctx.user.id, host))
          throw new TRPCError({
            code: "CONFLICT",
            message: "You have already reported this website.",
          });
        await addScamReport({
          userId: ctx.user.id,
          urlHost: host,
          category: input.category,
          description: input.description || null,
          createdAt: new Date(),
        });
        return { success: true, host } as const;
      }),
  }),
});
export type AppRouter = typeof appRouter;
