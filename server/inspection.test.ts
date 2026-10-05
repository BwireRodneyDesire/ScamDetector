import { afterEach, describe, expect, it, vi } from "vitest";
import { inspectUrl } from "./inspection";

describe("inspectUrl", () => {
  afterEach(() => vi.restoreAllMocks());

  it("rejects private network addresses before fetching", async () => {
    await expect(inspectUrl("http://192.168.1.10/login")).rejects.toThrow("Private or local network");
  });

  it("keeps a recognized WhatsApp domain low risk despite weak page signals", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ status: 200, headers: { get: () => "text/html" }, text: async () => `<html><body><a href="https://cdn.whatsapp.net/a">cdn</a><div style="display:none">menu</div></body></html>` }));
    const result = await inspectUrl("https://web.whatsapp.com/");
    expect(result.verdict).toBe("Low risk");
    expect(result.allowlistedEntity).toBe("WhatsApp");
  });

  it("raises a high-risk verdict for an IP-hosted login form", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ status: 200, headers: { get: () => "text/html" }, text: async () => `<html><body><form action="https://other.example/login"><input type="password"></form><p>Urgent account login verification</p></body></html>` }));
    const result = await inspectUrl("http://8.8.8.8/login");
    expect(result.verdict).toBe("High risk");
    expect(result.riskScore).toBeGreaterThanOrEqual(45);
    expect(result.signals.some((signal) => signal.id === "ip-host" && signal.severity === "high")).toBe(true);
  });

  it("returns friendly errors for invalid URLs", async () => {
    await expect(inspectUrl("not a valid url")).rejects.toThrow("cannot contain spaces");
  });

  it("counts absolute, protocol-relative, data, and inline-script links", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      status: 200,
      headers: { get: () => "text/html" },
      text: async () => `<a href="/local">local</a><a href="https://external.example/a">absolute</a><a href="//cdn.example/a">protocol</a><a data-href="https://data.example/a">data</a><script>window.location.href = "https://script.example/a";</script>`,
    }));
    const result = await inspectUrl("https://movieboxfilm.com/");
    const external = result.signals.find((signal) => signal.id === "external-links");
    expect(external?.evidence).toContain("4 external");
    expect(external?.evidence).toContain("1 internal");
  });

  it("marks page-only checks as not checked when fetching fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
    const result = await inspectUrl("https://unreachable.example/");
    for (const id of ["forms", "cross-form", "external-links", "hidden", "favicon"]) {
      expect(result.signals.find((signal) => signal.id === id)?.status).toBe("not_checked");
    }
    expect(result.signals.find((signal) => signal.id === "https")?.evidence).toContain("did not respond reliably");
  });
});
