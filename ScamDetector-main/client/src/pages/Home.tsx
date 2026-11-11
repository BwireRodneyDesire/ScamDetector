import jsQR from "jsqr";
import { useEffect, useMemo, useRef, useState } from "react";
import { trpc } from "@/lib/trpc";
import { startLogin } from "@/const";
import { useAuth } from "@/_core/hooks/useAuth";
import { Streamdown } from "streamdown";
import SiteHeader from "@/components/SiteHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  Clipboard,
  ClipboardCheck,
  ExternalLink,
  FileText,
  Globe2,
  Info,
  ListChecks,
  LockKeyhole,
  Radar,
  QrCode,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
} from "lucide-react";

type Result = NonNullable<
  ReturnType<typeof trpc.detector.check.useMutation>["data"]
>;
type Signal = Result["signals"][number];
type HistoryItem = Pick<Result, "url" | "verdict" | "riskScore" | "checkedAt">;
type Explanation = { text: string; source: "ai" | "fallback" };
const categories = [
  "URL structure",
  "Page signals",
  "HTTPS / TLS",
  "Reputation",
] as const;
const sampleUrls = [
  "https://web.whatsapp.com/",
  "https://secure-login-whatsapp-account.example.com/verify",
];
const phases = ["Checking URL", "Fetching page", "Analyzing links", "Done"];

function verdictTone(verdict: Result["verdict"]) {
  if (verdict === "High risk")
    return {
      color: "text-[#ffb4ab]",
      bg: "bg-[#ff6b5f]/15",
      border: "border-[#ff6b5f]/30",
      bar: "bg-[#ff6b5f]",
      icon: ShieldAlert,
    };
  if (verdict === "Review")
    return {
      color: "text-[#ffd28a]",
      bg: "bg-[#f3b74f]/15",
      border: "border-[#f3b74f]/30",
      bar: "bg-[#f3b74f]",
      icon: AlertTriangle,
    };
  return {
    color: "text-[#9bf3c1]",
    bg: "bg-[#6ee7a5]/15",
    border: "border-[#6ee7a5]/30",
    bar: "bg-[#6ee7a5]",
    icon: ShieldCheck,
  };
}
function signalTone(signal: Signal) {
  if (signal.status === "not_checked")
    return { color: "text-[#9aa7a5]", bg: "bg-[#9aa7a5]/10", icon: Info };
  if (signal.status === "passed" || signal.severity === "low")
    return { color: "text-[#9bf3c1]", bg: "bg-[#6ee7a5]/10", icon: Check };
  if (signal.severity === "high")
    return {
      color: "text-[#ffb4ab]",
      bg: "bg-[#ff6b5f]/10",
      icon: TriangleAlert,
    };
  return { color: "text-[#ffd28a]", bg: "bg-[#f3b74f]/10", icon: Info };
}

function SignalRow({
  signal,
  open,
  onToggle,
}: {
  signal: Signal;
  open: boolean;
  onToggle: () => void;
}) {
  const tone = signalTone(signal);
  const Icon = tone.icon;
  return (
    <div className="rounded-xl border border-white/[0.09] bg-[#081018]/55">
      <button
        type="button"
        onClick={onToggle}
        className="phishguard-flex-child flex w-full min-w-0 items-start justify-between gap-3 px-3 py-3 text-left"
      >
        <span className="phishguard-flex-child flex min-w-0 items-start gap-3">
          <span
            className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${tone.bg} ${tone.color}`}
          >
            <Icon className="h-3.5 w-3.5" />
          </span>
          <span className="phishguard-wrap min-w-0">
            <span className="block text-sm font-medium text-[#e0e9e6]">
              {signal.label}
            </span>
            <span className="block text-xs text-[#c1cfcb]">
              {signal.evidence}
            </span>
          </span>
        </span>
        <span className="flex shrink-0 items-center gap-2">
          <span className={`text-[10px] font-semibold uppercase ${tone.color}`}>
            {signal.status === "not_checked"
              ? "Not checked"
              : signal.status === "passed"
                ? "Low"
                : signal.severity}
          </span>
          <ChevronDown
            className={`h-4 w-4 text-[#9fb0ac] transition ${open ? "rotate-180" : ""}`}
          />
        </span>
      </button>
      <div
        className={`overflow-hidden transition-all duration-300 ${open ? "max-h-40 opacity-100" : "max-h-0 opacity-0"}`}
      >
        <div className="border-t border-white/[0.07] px-3 pb-3 pt-2 text-xs leading-5 text-[#c1cfcb]">
          <span className="font-semibold text-[#e0e9e6]">
            Why this matters:{" "}
          </span>
          {signal.why}
        </div>
      </div>
    </div>
  );
}

function SignalList({ result }: { result: Result }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(
      result.signals
        .filter(signal => signal.severity !== "low")
        .map(signal => [signal.id, true])
    )
  );
  const [showPassed, setShowPassed] = useState(false);
  const grouped = categories.map(category => ({
    category,
    signals: result.signals.filter(signal => signal.category === category),
  }));
  const passedCount = result.signals.filter(
    signal => signal.severity === "low" && signal.status !== "not_checked"
  ).length;
  return (
    <Card className="border-white/10 bg-[#101b22]/90">
      <CardHeader className="pb-3">
        <div className="phishguard-flex-child flex min-w-0 flex-wrap items-center justify-between gap-3">
          <CardTitle className="text-base text-[#f4fbf8]">
            Why this result?
          </CardTitle>
          {result.allowlistedEntity && (
            <Badge className="max-w-full whitespace-normal text-center border-[#6ee7a5]/20 bg-[#6ee7a5]/10 text-[#9bf3c1]">
              Recognized: {result.allowlistedEntity}
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {grouped.map(({ category, signals }) => {
          const warnings = signals.filter(
            signal =>
              signal.severity !== "low" && signal.status !== "not_checked"
          );
          const notChecked = signals.filter(
            signal => signal.status === "not_checked"
          );
          const passed = signals.filter(
            signal =>
              signal.severity === "low" && signal.status !== "not_checked"
          );
          return (
            <div key={category}>
              <div className="mb-2 flex min-w-0 flex-wrap items-start justify-between gap-x-3 gap-y-1">
                <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#9fb0ac]">
                  {category}
                </p>
                {notChecked.length > 0 ? (
                  <span className="max-w-full text-right text-[10px] text-[#9aa7a5]">
                    {notChecked.length} not checked
                  </span>
                ) : (
                  warnings.length === 0 && (
                    <span className="max-w-full text-right text-[10px] text-[#9bf3c1]">
                      All checks passed
                    </span>
                  )
                )}
              </div>
              <div className="space-y-2">
                {warnings.map(signal => (
                  <SignalRow
                    key={signal.id}
                    signal={signal}
                    open={expanded[signal.id] !== false}
                    onToggle={() =>
                      setExpanded(current => ({
                        ...current,
                        [signal.id]: current[signal.id] === false,
                      }))
                    }
                  />
                ))}
              </div>
              {passed.length > 0 && (
                <div
                  className={`overflow-hidden transition-all duration-300 ${showPassed ? "mt-2 max-h-[1200px] opacity-100" : "max-h-0 opacity-0"}`}
                >
                  <div className="space-y-2">
                    {passed.map(signal => (
                      <SignalRow
                        key={signal.id}
                        signal={signal}
                        open={expanded[signal.id] === true}
                        onToggle={() =>
                          setExpanded(current => ({
                            ...current,
                            [signal.id]: !current[signal.id],
                          }))
                        }
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
        <button
          type="button"
          onClick={() => setShowPassed(value => !value)}
          className="flex w-full items-center justify-center gap-2 rounded-lg border border-white/[0.09] px-3 py-2.5 text-xs font-medium text-[#c1cfcb] transition hover:border-[#8df0b8]/30 hover:text-[#8df0b8]"
        >
          <ChevronDown
            className={`h-4 w-4 transition ${showPassed ? "rotate-180" : ""}`}
          />
          {showPassed ? "Hide" : "Show"} {passedCount} passed checks
        </button>
      </CardContent>
    </Card>
  );
}

function IntroCards() {
  return (
    <section className="grid gap-4 border-t border-white/10 pt-8 sm:grid-cols-3">
      {[
        {
          icon: Globe2,
          title: "URL intelligence",
          body: "Length, subdomains, symbols, host type, and HTTPS.",
        },
        {
          icon: ClipboardCheck,
          title: "Page inspection",
          body: "Forms, iframes, hidden elements, favicons, and links.",
        },
        {
          icon: LockKeyhole,
          title: "Responsible by design",
          body: "A signal, not a verdict. Never share passwords or payment details.",
        },
      ].map(({ icon: Icon, title, body }) => (
        <div
          key={title}
          className="rounded-2xl border border-white/10 bg-[#101b22]/55 p-5"
        >
          <Icon className="h-5 w-5 text-[#8df0b8]" />
          <h3 className="mt-5 text-sm font-semibold text-[#f4fbf8]">{title}</h3>
          <p className="mt-2 text-sm leading-6 text-[#c1cfcb]">{body}</p>
        </div>
      ))}
    </section>
  );
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [phase, setPhase] = useState("");
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [copied, setCopied] = useState(false);
  const [explanation, setExplanation] = useState<Explanation>({
    text: "",
    source: "ai",
  });
  const [showImport, setShowImport] = useState(false);
  const qrInputRef = useRef<HTMLInputElement>(null);
  const { user, isAuthenticated, loading: authLoading, logout } = useAuth();
  const utils = trpc.useUtils();
  const historyQuery = trpc.detector.history.useQuery(undefined, {
    enabled: isAuthenticated,
    retry: false,
  });
  const importHistory = trpc.detector.importHistory.useMutation({
    onSuccess: async () => {
      setHistory([]);
      localStorage.removeItem("phishguard-history");
      setShowImport(false);
      await historyQuery.refetch();
    },
  });
  const deleteHistory = trpc.detector.deleteHistory.useMutation({
    onSuccess: () => historyQuery.refetch(),
  });
  const explain = trpc.detector.explain.useMutation({
    onSuccess: setExplanation,
    onError: () =>
      setExplanation({
        source: "fallback",
        text: "The site could not be reached reliably, so some page checks were unavailable. The scan found the most important URL patterns shown below; these patterns can occur on legitimate sites, so verify the address independently and avoid entering sensitive information.",
      }),
  });
  const checkUrl = trpc.detector.check.useMutation({
    onSuccess: async data => {
      setPhase("Done");
      setExplanation({ text: "", source: "ai" });
      explain.mutate({ result: data });
      if (isAuthenticated) await utils.detector.history.invalidate();
      else
        setHistory(current =>
          [
            {
              url: data.url,
              verdict: data.verdict,
              riskScore: data.riskScore,
              checkedAt: data.checkedAt,
            },
            ...current.filter(item => item.url !== data.url),
          ].slice(0, 50)
        );
    },
  });
  const scanMessage = trpc.detector.scanMessage.useMutation();
  const result = checkUrl.data;
  const displayHistory: HistoryItem[] = isAuthenticated
    ? (historyQuery.data ?? []).map(item => ({
        url: item.url,
        verdict: item.verdict as HistoryItem["verdict"],
        riskScore: item.riskScore,
        checkedAt:
          item.checkedAt instanceof Date
            ? item.checkedAt.toISOString()
            : String(item.checkedAt),
      }))
    : history;
  const tone = result ? verdictTone(result.verdict) : null;
  const VerdictIcon = tone?.icon ?? ShieldCheck;
  useEffect(() => {
    try {
      setHistory(
        JSON.parse(localStorage.getItem("phishguard-history") ?? "[]")
      );
    } catch {
      setHistory([]);
    }
  }, []);
  useEffect(() => {
    localStorage.setItem("phishguard-history", JSON.stringify(history));
  }, [history]);
  useEffect(() => {
    if (isAuthenticated && history.length > 0) setShowImport(true);
  }, [isAuthenticated]);
  useEffect(() => {
    if (!checkUrl.isPending) return;
    let index = 0;
    setPhase(phases[index]);
    const timer = window.setInterval(() => {
      index = Math.min(index + 1, phases.length - 2);
      setPhase(phases[index]);
    }, 850);
    return () => window.clearInterval(timer);
  }, [checkUrl.isPending]);
  const grouped = useMemo(
    () =>
      result
        ? categories.map(category => ({
            category,
            signals: result.signals.filter(
              signal => signal.category === category
            ),
          }))
        : [],
    [result]
  );
  const breakdown = grouped.map(({ category, signals }) => ({
    category,
    total: signals.filter(signal => signal.status !== "not_checked").length,
    passed: signals.filter(
      signal => signal.status === "passed" || signal.status === "info"
    ).length,
    notChecked: signals.filter(signal => signal.status === "not_checked")
      .length,
  }));
  const reportText = result
    ? `PhishGuard report\nURL: ${result.url}\nVerdict: ${result.verdict}\nRisk score: ${result.riskScore}/100\n\nWhy this result:\n${result.reasons.map(reason => `- ${reason}`).join("\n")}\n\nSignals:\n${result.signals.map(signal => `- [${signal.severity}] ${signal.label}: ${signal.evidence}`).join("\n")}`
    : "";
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!url.trim() || checkUrl.isPending) return;
    checkUrl.reset();
    explain.reset();
    checkUrl.mutate({ url: url.trim() });
  };
  const clearResult = () => {
    checkUrl.reset();
    explain.reset();
    setExplanation({ text: "", source: "ai" });
    setPhase("");
  };
  const copyReport = async () => {
    if (!reportText) return;
    await navigator.clipboard.writeText(reportText);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };
  const chooseHistory = (item: HistoryItem) => {
    setUrl(item.url);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  const importGuestHistory = () =>
    importHistory.mutate({
      items: history.map(item => ({
        url: item.url,
        verdict: item.verdict,
        riskScore: item.riskScore,
        checkedAt: item.checkedAt,
      })),
    });
  const scanQrImage = (file: File) => {
    const imageUrl = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      try {
        const canvas = document.createElement("canvas");
        canvas.width = image.naturalWidth;
        canvas.height = image.naturalHeight;
        const context = canvas.getContext("2d");
        if (!context) throw new Error("Could not read the uploaded image.");
        context.drawImage(image, 0, 0);
        const imageData = context.getImageData(
          0,
          0,
          canvas.width,
          canvas.height
        );
        const decoded = jsQR(
          imageData.data,
          imageData.width,
          imageData.height
        );
        if (!decoded?.data)
          throw new Error(
            "No QR code was found. Upload a clearer image with the code fully visible."
          );
        setUrl(decoded.data);
        setMessage("");
        window.scrollTo({ top: 0, behavior: "smooth" });
      } catch (error) {
        scanMessage.reset();
        checkUrl.reset();
        window.alert(
          error instanceof Error
            ? error.message
            : "The QR code could not be read."
        );
      } finally {
        URL.revokeObjectURL(imageUrl);
      }
    };
    image.onerror = () => {
      URL.revokeObjectURL(imageUrl);
      window.alert("The uploaded image could not be opened.");
    };
    image.src = imageUrl;
  };
  const handleQrFile = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file) scanQrImage(file);
  };

  return (
    <div className="min-h-screen bg-[#081018] text-[#edf5f2]">
      <div className="pointer-events-none fixed inset-0 -z-0 opacity-80">
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-[#1d8b70]/20 blur-3xl" />
        <div className="absolute right-[-10rem] top-40 h-[30rem] w-[30rem] rounded-full bg-[#c58b4a]/10 blur-3xl" />
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.025)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.025)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:linear-gradient(to_bottom,black,transparent_80%)]" />
      </div>
      <SiteHeader />

      <main className="relative z-10 mx-auto max-w-7xl px-6 pb-20 lg:px-10">
        <section
          id="scan"
          className="phishguard-grid grid min-w-0 gap-12 pb-16 pt-12 lg:grid-cols-[1.05fr_0.95fr] lg:items-end lg:pt-20"
        >
          <div className="min-w-0 max-w-3xl">
            <div className="mb-7 inline-flex max-w-full items-center gap-2 rounded-full border border-[#8df0b8]/20 bg-[#8df0b8]/[0.07] px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.18em] text-[#8df0b8]">
              <Sparkles className="h-3.5 w-3.5" /> Early warning for the web
            </div>
            <h1 className="phishguard-wrap max-w-3xl text-[clamp(2.6rem,11vw,4.5rem)] font-semibold leading-[0.98] tracking-[-0.055em] text-[#f4fbf8] sm:text-7xl">
              Check before you <span className="text-[#8df0b8]">click.</span>
            </h1>
            <p className="mt-7 max-w-xl text-base leading-7 text-[#c1cfcb] sm:text-lg">
              PhishGuard reads the address, page structure, links, forms, and
              transport signals behind a website to surface patterns commonly
              seen in phishing and scam pages.
            </p>
            <div className="mt-8 flex flex-wrap gap-x-6 gap-y-3 text-xs text-[#c1cfcb]">
              <span className="inline-flex items-center gap-2">
                <Globe2 className="h-4 w-4 text-[#8df0b8]" /> URL structure
              </span>
              <span className="inline-flex items-center gap-2">
                <ClipboardCheck className="h-4 w-4 text-[#8df0b8]" /> Page
                signals
              </span>
              <span className="inline-flex items-center gap-2">
                <LockKeyhole className="h-4 w-4 text-[#8df0b8]" /> HTTPS / TLS
              </span>
            </div>
          </div>
          <Card className="border-white/10 bg-[#101b22]/90 shadow-[0_25px_90px_rgba(0,0,0,0.22)] backdrop-blur">
            <CardHeader className="border-b border-white/10 pb-5">
              <div className="flex min-w-0 flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#9fb0ac]">
                    Scan a website
                  </p>
                  <CardTitle className="mt-2 text-xl text-[#f4fbf8]">
                    Is this link safe?
                  </CardTitle>
                </div>
                <div className="rounded-lg border border-[#8df0b8]/20 bg-[#8df0b8]/10 p-2 text-[#8df0b8]">
                  <ShieldCheck className="h-5 w-5" />
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-6">
              <form onSubmit={submit} className="space-y-3">
                <label
                  htmlFor="url"
                  className="text-xs font-medium text-[#e0e9e6]"
                >
                  Website address
                </label>
                <div className="flex flex-col gap-3 sm:flex-row">
                  <Input
                    id="url"
                    value={url}
                    onChange={event => setUrl(event.target.value)}
                    placeholder="https://example.com"
                    className="h-12 border-white/10 bg-[#081018] text-[#f4fbf8] placeholder:text-[#8d9f9b] focus-visible:ring-[#8df0b8]"
                    autoComplete="url"
                  />
                  <Button
                    type="submit"
                    disabled={!url.trim() || checkUrl.isPending}
                    className="h-12 shrink-0 bg-[#8df0b8] px-5 font-semibold text-[#09130f] hover:bg-[#b0f7cd]"
                  >
                    {checkUrl.isPending ? "Scanning…" : "Check URL"}
                    {!checkUrl.isPending && (
                      <ArrowRight className="ml-2 h-4 w-4" />
                    )}
                  </Button>
                </div>
              </form>
              <div className="mt-6 border-t border-white/10 pt-5">
                <label
                  htmlFor="message"
                  className="text-xs font-medium text-[#e0e9e6]"
                >
                  Paste a WhatsApp, SMS, or email message
                </label>
                <textarea
                  id="message"
                  value={message}
                  onChange={event => setMessage(event.target.value)}
                  placeholder="Paste the message here. PhishGuard will find up to 5 links."
                  maxLength={10_000}
                  className="mt-2 min-h-24 w-full resize-y rounded-md border border-white/10 bg-[#081018] px-3 py-2 text-sm text-[#f4fbf8] outline-none placeholder:text-[#8d9f9b] focus:ring-2 focus:ring-[#8df0b8]"
                />
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    disabled={!message.trim() || scanMessage.isPending}
                    onClick={() => scanMessage.mutate({ message })}
                    className="border-white/10 text-[#c1cfcb] hover:bg-white/5 hover:text-[#f4fbf8]"
                  >
                    {scanMessage.isPending ? "Scanning links…" : "Scan links"}
                    {!scanMessage.isPending && (
                      <ArrowRight className="ml-2 h-4 w-4" />
                    )}
                  </Button>
                  <input
                    ref={qrInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleQrFile}
                    className="hidden"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => qrInputRef.current?.click()}
                    className="border-white/10 text-[#c1cfcb] hover:bg-white/5 hover:text-[#f4fbf8]"
                  >
                    <QrCode className="mr-2 h-4 w-4" /> Scan QR image
                  </Button>
                </div>
                <p className="mt-2 text-[11px] leading-5 text-[#9fb0ac]">
                  Do not paste passwords, OTPs, or private conversations.
                  Uploaded QR images are decoded in your browser.
                </p>
                {scanMessage.error && (
                  <div className="mt-3 rounded-lg border border-[#ff6b5f]/20 bg-[#ff6b5f]/[0.08] p-3 text-xs text-[#ffb4ab]">
                    {scanMessage.error.message}
                  </div>
                )}
                {scanMessage.data && (
                  <div className="mt-4 space-y-2">
                    <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#9fb0ac]">
                      Found {scanMessage.data.extractedUrls.length} link
                      {scanMessage.data.extractedUrls.length === 1 ? "" : "s"}
                    </p>
                    {scanMessage.data.results.map(item => (
                      <button
                        key={item.url}
                        type="button"
                        onClick={() => item.result && setUrl(item.result.url)}
                        className="flex w-full items-start justify-between gap-3 rounded-lg border border-white/10 bg-[#081018]/70 p-3 text-left transition hover:border-[#8df0b8]/40"
                      >
                        <span className="min-w-0">
                          <span className="block break-all text-xs text-[#c1cfcb]">
                            {item.url}
                          </span>
                          <span className="mt-1 block text-[11px] text-[#9fb0ac]">
                            {item.error ??
                              `${item.result?.verdict} · risk ${item.result?.riskScore}/100`}
                          </span>
                        </span>
                        {item.result && (
                          <span
                            className={`shrink-0 text-[10px] font-semibold uppercase ${verdictTone(item.result.verdict).color}`}
                          >
                            {item.result.verdict}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="mt-5 flex flex-wrap items-center gap-2">
                <span className="text-[11px] text-[#c1cfcb]">Try a sample</span>
                {sampleUrls.map(sample => (
                  <button
                    key={sample}
                    type="button"
                    onClick={() => setUrl(sample)}
                    className="rounded-full border border-white/10 px-2.5 py-1 font-mono text-[10px] text-[#c1cfcb] transition hover:border-[#8df0b8]/40 hover:text-[#8df0b8]"
                  >
                    {sample.replace("https://", "")}
                  </button>
                ))}
              </div>
              {checkUrl.isPending && (
                <div className="mt-6 flex items-center justify-between gap-2 rounded-xl border border-white/10 bg-[#081018]/70 p-3">
                  {phases.map((item, index) => (
                    <div
                      key={item}
                      className={`flex items-center gap-1.5 text-[10px] ${item === phase ? "text-[#8df0b8]" : "text-[#8d9f9b]"}`}
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${item === phase ? "animate-pulse bg-[#8df0b8]" : "bg-current"}`}
                      />
                      {item}
                      {index < 3 && (
                        <span className="ml-1 hidden text-[#566762] sm:inline">
                          →
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {checkUrl.error && (
                <div className="mt-5 flex gap-3 rounded-xl border border-[#ff6b5f]/20 bg-[#ff6b5f]/[0.08] p-3 text-sm text-[#ffb4ab]">
                  <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{checkUrl.error.message}</span>
                </div>
              )}
            </CardContent>
          </Card>
        </section>
        {result && tone ? (
          <section className="animate-in fade-in slide-in-from-bottom-3 duration-500">
            <div className="mb-5 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#9fb0ac]">
                  Latest inspection
                </p>
                <h2 className="mt-2 break-all text-2xl font-semibold tracking-tight text-[#f4fbf8]">
                  {result.url}
                </h2>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  onClick={copyReport}
                  className="w-fit text-[#c1cfcb] hover:bg-white/5 hover:text-[#f4fbf8]"
                >
                  {copied ? (
                    <Check className="mr-2 h-4 w-4" />
                  ) : (
                    <Clipboard className="mr-2 h-4 w-4" />
                  )}
                  {copied ? "Copied" : "Copy report"}
                </Button>
                <Button
                  variant="ghost"
                  onClick={clearResult}
                  className="w-fit text-[#c1cfcb] hover:bg-white/5 hover:text-[#f4fbf8]"
                >
                  <RotateCcw className="mr-2 h-4 w-4" /> Clear
                </Button>
                <a
                  href={`/report?url=${encodeURIComponent(result.url)}`}
                  className="inline-flex h-9 w-fit items-center justify-center rounded-md border border-[#f3b74f]/30 px-3 text-xs font-medium text-[#ffd28a] transition hover:bg-[#f3b74f]/10"
                >
                  Report this site
                </a>
              </div>
            </div>
            <div className="phishguard-grid grid min-w-0 items-start gap-5 lg:grid-cols-[0.8fr_1.2fr]">
              <div className="space-y-5 lg:sticky lg:top-6 lg:self-start">
                <Card
                  className={`min-w-0 overflow-hidden border ${tone.border} bg-[#101b22]/90`}
                >
                  <CardContent className="p-6 sm:p-8">
                    <div className="flex min-w-0 flex-wrap items-start justify-between gap-4">
                      <div
                        className={`flex h-12 w-12 items-center justify-center rounded-2xl ${tone.bg} ${tone.color}`}
                      >
                        <VerdictIcon className="h-6 w-6" />
                      </div>
                      <Badge
                        className={`hidden border sm:inline-flex ${tone.border} ${tone.bg} ${tone.color}`}
                      >
                        {result.verdict}
                      </Badge>
                    </div>
                    <p className="phishguard-wrap mt-7 text-[clamp(1.7rem,7vw,1.875rem)] font-semibold tracking-tight text-[#f4fbf8]">
                      {result.headline}
                    </p>
                    <p className="phishguard-wrap mt-3 text-sm leading-6 text-[#c1cfcb]">
                      {result.summary}
                    </p>
                    <div className="mt-8 flex min-w-0 items-center justify-between gap-3 sm:items-end">
                      <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#9fb0ac]">
                        Risk score
                      </span>
                      <span className="flex min-w-0 items-center justify-end gap-2">
                        <Badge
                          className={`inline-flex sm:hidden ${tone.border} ${tone.bg} ${tone.color}`}
                        >
                          {result.verdict}
                        </Badge>
                        <span
                          className={`phishguard-wrap text-3xl font-semibold ${tone.color}`}
                        >
                          {result.riskScore}
                          <span className="text-base text-[#9fb0ac]">/100</span>
                        </span>
                      </span>
                    </div>
                    <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/10">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${tone.bar}`}
                        style={{ width: `${Math.max(3, result.riskScore)}%` }}
                      />
                    </div>
                    <p className="mt-4 text-xs text-[#9fb0ac]">
                      Confidence: {Math.round(result.confidence * 100)}% ·
                      Heuristic analysis
                    </p>
                  </CardContent>
                </Card>
                <Card className="border-white/10 bg-[#101b22]/90">
                  <CardHeader className="pb-3">
                    <div className="flex items-center gap-2">
                      <ListChecks className="h-4 w-4 text-[#8df0b8]" />
                      <CardTitle className="text-sm text-[#f4fbf8]">
                        Why this result
                      </CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-3">
                      {result.reasons.map(reason => (
                        <li
                          key={reason}
                          className="flex items-start gap-2.5 text-sm leading-5 text-[#c1cfcb]"
                        >
                          <span
                            className={`mt-2 h-1.5 w-1.5 shrink-0 rounded-full ${tone.bar}`}
                          />
                          <span className="phishguard-wrap">{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
                <Card className="border-[#8df0b8]/15 bg-[#8df0b8]/[0.05]">
                  <CardContent className="p-5">
                    <div className="flex min-w-0 items-start gap-3">
                      <Sparkles className="mt-0.5 h-5 w-5 shrink-0 text-[#8df0b8]" />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="font-semibold text-[#f4fbf8]">
                            What this means
                          </h3>
                          <Badge className="border-[#8df0b8]/20 bg-[#8df0b8]/10 text-[10px] text-[#9bf3c1]">
                            {explanation.source === "ai"
                              ? "AI-generated"
                              : "Summary"}
                          </Badge>
                        </div>
                        {explain.isPending ? (
                          <div className="mt-3 space-y-2">
                            <div className="h-3 w-11/12 animate-pulse rounded bg-white/10" />
                            <div className="h-3 w-8/12 animate-pulse rounded bg-white/10" />
                          </div>
                        ) : (
                          <p className="phishguard-wrap mt-3 text-sm leading-6 text-[#c1cfcb]">
                            <Streamdown>
                              {explanation.text ||
                                "The explanation will appear here."}
                            </Streamdown>
                          </p>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card className="border-white/10 bg-[#101b22]/90">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm text-[#f4fbf8]">
                      Category breakdown
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {breakdown.map(
                      ({ category, total, passed, notChecked }) => (
                        <div key={category}>
                          <div className="flex min-w-0 flex-wrap items-start justify-between gap-x-3 gap-y-1 text-xs">
                            <span className="text-[#c1cfcb]">{category}</span>
                            <span className="max-w-full text-right font-mono text-[#9fb0ac]">
                              {notChecked
                                ? `${notChecked} not checked`
                                : `${passed} of ${total} checks passed`}
                            </span>
                          </div>
                          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                            <div
                              className={`h-full rounded-full transition-all duration-500 ${notChecked ? "bg-[#9aa7a5]" : "bg-[#6ee7a5]"}`}
                              style={{
                                width: `${total ? (passed / total) * 100 : 0}%`,
                              }}
                            />
                          </div>
                        </div>
                      )
                    )}
                  </CardContent>
                </Card>
                <Card className="border-white/10 bg-[#101b22]/90">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm text-[#f4fbf8]">
                      Domain info
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="grid min-w-0 grid-cols-2 gap-4 text-xs sm:grid-cols-3">
                    <div className="min-w-0">
                      <p className="text-[#9fb0ac]">Age</p>
                      <p className="phishguard-wrap mt-1 font-medium text-[#e0e9e6]">
                        {result.reputation.domainAgeDays === null
                          ? "Not checked"
                          : `${result.reputation.domainAgeDays} days`}
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[#9fb0ac]">Registrar</p>
                      <p className="phishguard-wrap mt-1 font-medium text-[#e0e9e6]">
                        {result.reputation.registrar ?? "Not checked"}
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[#9fb0ac]">Expiry</p>
                      <p className="phishguard-wrap mt-1 font-medium text-[#e0e9e6]">
                        {result.reputation.expiryDate
                          ? result.reputation.expiryDate.slice(0, 10)
                          : "Not checked"}
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[#9fb0ac]">Hosting</p>
                      <p className="phishguard-wrap mt-1 font-medium text-[#e0e9e6]">
                        {result.reputation.hostingCountry ?? "Not checked"}
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[#9fb0ac]">Popularity</p>
                      <p className="phishguard-wrap mt-1 font-medium text-[#e0e9e6]">
                        {result.reputation.popularityRank
                          ? `#${result.reputation.popularityRank}`
                          : "Not checked"}
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[#9fb0ac]">Redirects</p>
                      <p className="phishguard-wrap mt-1 font-medium text-[#e0e9e6]">
                        {Math.max(
                          0,
                          result.reputation.redirectChain.length - 1
                        )}
                      </p>
                    </div>
                  </CardContent>
                </Card>
                <details className="rounded-xl border border-white/10 bg-[#101b22]/70 p-4 text-xs text-[#c1cfcb]">
                  <summary className="cursor-pointer font-semibold text-[#f4fbf8]">
                    How the score is calculated
                  </summary>
                  <ul className="mt-3 space-y-2 leading-5">
                    <li>
                      <strong className="text-[#e0e9e6]">Strong:</strong>{" "}
                      blocklist matches +65, brand lookalike +30, cross-domain
                      login redirect +34, new domain with login form +32.
                    </li>
                    <li>
                      <strong className="text-[#e0e9e6]">Moderate:</strong>{" "}
                      suspicious host language, form destinations, excessive
                      subdomains, and cross-domain redirects add smaller
                      weights.
                    </li>
                    <li>
                      <strong className="text-[#e0e9e6]">Context:</strong>{" "}
                      Tranco top-10k popularity lowers the score cap when no
                      blocklist hit exists; popularity alone is not proof of
                      safety.
                    </li>
                  </ul>
                </details>
                <p className="px-1 text-xs leading-5 text-[#9fb0ac]">
                  Note: this tool detects phishing patterns. It does not judge
                  whether a site is legal or free of ads/malware.
                </p>
              </div>
              <SignalList result={result} />
            </div>
          </section>
        ) : (
          <IntroCards />
        )}
        {(displayHistory.length > 0 || isAuthenticated) && (
          <section className="mt-16 border-t border-white/10 pt-8">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-[#8df0b8]" />
                  <h2 className="text-sm font-semibold text-[#f4fbf8]">
                    Recent scans
                  </h2>
                  <span className="text-xs text-[#c1cfcb]">
                    {isAuthenticated
                      ? "Saved to your account"
                      : "Stored only in this browser"}
                  </span>
                </div>
                {isAuthenticated && (
                  <p className="mt-2 text-xs text-[#9fb0ac]">
                    Signed-in scans (URL, score, date) are saved to your
                    account. You can delete them anytime.
                  </p>
                )}
              </div>
              {isAuthenticated && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => deleteHistory.mutate()}
                  disabled={deleteHistory.isPending || !displayHistory.length}
                  className="w-fit text-[#ffb4ab] hover:bg-[#ff6b5f]/10 hover:text-[#ffb4ab]"
                >
                  Delete my history
                </Button>
              )}
            </div>
            {showImport && isAuthenticated && history.length > 0 && (
              <div className="mt-4 flex flex-col gap-3 rounded-xl border border-[#8df0b8]/20 bg-[#8df0b8]/[0.06] p-4 text-sm text-[#c1cfcb] sm:flex-row sm:items-center sm:justify-between">
                <span>
                  Import your {history.length} guest scan
                  {history.length === 1 ? "" : "s"} into your account?
                </span>
                <span className="flex gap-2">
                  <Button
                    size="sm"
                    onClick={importGuestHistory}
                    disabled={importHistory.isPending}
                    className="bg-[#8df0b8] text-[#09130f]"
                  >
                    {importHistory.isPending ? "Importing…" : "Import"}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setShowImport(false)}
                    className="text-[#c1cfcb]"
                  >
                    Not now
                  </Button>
                </span>
              </div>
            )}
            {displayHistory.length > 0 && (
              <div className="mt-4 grid gap-2">
                {displayHistory.map(item => {
                  const itemTone = verdictTone(item.verdict);
                  return (
                    <button
                      type="button"
                      key={`${item.url}-${item.checkedAt}`}
                      onClick={() => chooseHistory(item)}
                      className="flex flex-col gap-2 rounded-xl border border-white/[0.09] bg-[#101b22]/55 p-3 text-left transition hover:border-[#8df0b8]/30 sm:flex-row sm:items-center sm:justify-between"
                    >
                      <span className="phishguard-wrap min-w-0 text-sm text-[#e0e9e6]">
                        {item.url}
                      </span>
                      <span className="flex shrink-0 items-center gap-3">
                        <span
                          className={`text-xs font-semibold ${itemTone.color}`}
                        >
                          {item.verdict}
                        </span>
                        <span className="font-mono text-xs text-[#c1cfcb]">
                          {item.riskScore}/100
                        </span>
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </section>
        )}
        <section
          id="about"
          className="mt-16 grid gap-6 border-t border-white/10 pt-10 lg:grid-cols-[1fr_1fr]"
        >
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#8df0b8]">
              About & limitations
            </p>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight text-[#f4fbf8]">
              A useful signal, not a promise.
            </h2>
          </div>
          <div className="phishguard-wrap min-w-0 space-y-3 text-sm leading-6 text-[#c1cfcb]">
            <p>
              PhishGuard combines URL structure, page signals, and HTTPS / TLS
              observations. It weights strong clues such as lookalike domains,
              IP hosts, cross-domain forms, and missing HTTPS more heavily than
              weak clues such as hidden elements or external links.
            </p>
            <p>
              Heuristic analysis can produce false positives and false
              negatives. Do not use this result as the only basis for trusting a
              site, and never enter passwords or payment details into an
              unfamiliar page.
            </p>
          </div>
        </section>
      </main>
      <footer className="relative z-10 mx-auto flex max-w-7xl flex-col gap-2 border-t border-white/10 px-6 py-6 text-xs text-[#c1cfcb] sm:flex-row sm:items-center sm:justify-between lg:px-10">
        <span>PhishGuard · Makerere University project prototype</span>
        <span className="inline-flex items-center gap-1.5">
          <ExternalLink className="h-3.5 w-3.5" /> Heuristic analysis, not a
          guarantee of safety.
        </span>
      </footer>
    </div>
  );
}
