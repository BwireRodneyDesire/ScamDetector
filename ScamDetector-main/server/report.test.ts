import { beforeEach, describe, expect, it, vi } from "vitest";

const dbMocks = vi.hoisted(() => ({
  addScamReport: vi.fn(),
  addScanHistory: vi.fn(),
  clearScanHistory: vi.fn(),
  countUserReportsSince: vi.fn(),
  getCommunityReports: vi.fn(),
  hasUserReportedHost: vi.fn(),
  listScanHistory: vi.fn(),
  trimScanHistory: vi.fn(),
}));
const inspectMock = vi.hoisted(() => ({ inspectUrl: vi.fn() }));
vi.mock("./db", () => dbMocks);
vi.mock("./inspection", () => inspectMock);

import { appRouter } from "./routers";

const user = {
  id: 7,
  openId: "test-user",
  name: "Test User",
  email: "test@example.com",
  loginMethod: "test",
  role: "user",
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};
const ctx = {
  user,
  req: { headers: {}, protocol: "https" },
  res: { clearCookie: vi.fn() },
} as any;
const guestCtx = {
  user: undefined,
  req: { headers: {}, protocol: "https" },
  res: { clearCookie: vi.fn() },
} as any;

const baseResult = {
  url: "https://example.com/",
  verdict: "Low risk",
  classification: "legitimate",
  confidence: 0.8,
  riskScore: 8,
  headline: "No strong phishing signals found",
  summary: "Looks broadly typical.",
  reasons: [],
  signals: [],
  features: [],
  checkedAt: new Date().toISOString(),
  fetchStatus: 200,
  allowlistedEntity: null,
};

describe("detector.submitReport", () => {
  it("requires authentication", async () => {
    await expect(
      appRouter
        .createCaller(guestCtx)
        .detector.submitReport({
          url: "https://example.com",
          category: "Other",
          description: "",
        })
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
  it("stores a valid report and rejects duplicates", async () => {
    dbMocks.countUserReportsSince.mockResolvedValue(0);
    dbMocks.hasUserReportedHost
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);
    await expect(
      appRouter
        .createCaller(ctx)
        .detector.submitReport({
          url: "https://example.com/login",
          category: "Fake login page",
          description: "Asked for a code",
        })
    ).resolves.toMatchObject({ success: true, host: "example.com" });
    await expect(
      appRouter
        .createCaller(ctx)
        .detector.submitReport({
          url: "https://example.com/",
          category: "Other",
          description: "",
        })
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(dbMocks.addScamReport).toHaveBeenCalledTimes(1);
  });
  it("enforces the five-per-hour user limit", async () => {
    dbMocks.countUserReportsSince.mockResolvedValue(5);
    await expect(
      appRouter
        .createCaller(ctx)
        .detector.submitReport({
          url: "https://another.example",
          category: "Other",
          description: "",
        })
    ).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
  });
});

describe("community report enrichment", () => {
  it("adds an unverified community signal to scan results", async () => {
    inspectMock.inspectUrl.mockResolvedValue(baseResult);
    dbMocks.getCommunityReports.mockResolvedValue({
      reportCount: 3,
      userCount: 2,
      categories: [
        { category: "Fake login page", count: 2 },
        { category: "Other", count: 1 },
      ],
    });
    const result = await appRouter
      .createCaller(guestCtx)
      .detector.check({ url: "https://example.com" });
    expect(result.communityReports?.reportCount).toBe(3);
    expect(result.signals).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "community-reports",
          severity: "medium",
          evidence: expect.stringContaining("2 users reported"),
        }),
      ])
    );
  });
});

describe("detector.scanMessage", () => {
  beforeEach(() => vi.clearAllMocks());

  it("extracts links, scans each one, and records authenticated history", async () => {
    dbMocks.getCommunityReports.mockResolvedValue({
      reportCount: 0,
      userCount: 0,
      categories: [],
    });
    inspectMock.inspectUrl
      .mockResolvedValueOnce({ ...baseResult, url: "https://example.com/" })
      .mockResolvedValueOnce({
        ...baseResult,
        url: "https://secure.example.org/login",
        verdict: "Review",
        riskScore: 30,
      });

    const result = await appRouter.createCaller(ctx).detector.scanMessage({
      message:
        "Check https://example.com and www.example.org/login. Do not share your password.",
    });

    expect(result.extractedUrls).toEqual([
      "https://example.com/",
      "https://www.example.org/login",
    ]);
    expect(result.results).toHaveLength(2);
    expect(inspectMock.inspectUrl).toHaveBeenCalledTimes(2);
    expect(dbMocks.addScanHistory).toHaveBeenCalledTimes(2);
  });

  it("rejects messages containing more than five links", async () => {
    const message = Array.from(
      { length: 6 },
      (_, index) => `https://example${index}.com`
    ).join(" ");
    await expect(
      appRouter.createCaller(guestCtx).detector.scanMessage({ message })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(inspectMock.inspectUrl).not.toHaveBeenCalled();
  });
});
