import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { startLogin } from "@/const";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { AlertTriangle, CheckCircle2, Flag, Send } from "lucide-react";
import SiteHeader from "@/components/SiteHeader";

const categories = [
  "Fake login page",
  "Fake prize or giveaway",
  "Investment scam",
  "Mobile money scam",
  "Other",
] as const;

function initialUrl() {
  try {
    return new URLSearchParams(window.location.search).get("url") ?? "";
  } catch {
    return "";
  }
}

export default function Report() {
  const { isAuthenticated, loading } = useAuth();
  const [url, setUrl] = useState(initialUrl);
  const [category, setCategory] = useState<(typeof categories)[number]>(
    categories[0]
  );
  const [description, setDescription] = useState("");
  const [honeypot, setHoneypot] = useState("");
  const report = trpc.detector.submitReport.useMutation();
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!url.trim() || report.isPending) return;
    report.mutate({ url: url.trim(), category, description, honeypot });
  };
  return (
    <div className="min-h-screen bg-[#081018] text-[#edf5f2]">
      <SiteHeader />
      <main className="relative z-10 mx-auto max-w-3xl px-6 pb-20 pt-10 lg:px-10">
        <div className="mb-8">
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#8df0b8]">
            Community safety signal
          </p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-[#f4fbf8] sm:text-5xl">
            Report a scam
          </h1>
          <p className="mt-4 max-w-2xl leading-7 text-[#c1cfcb]">
            Share a website that looked deceptive. Reports are unverified
            community opinions and help PhishGuard add context—not a final
            verdict.
          </p>
        </div>
        {!loading && !isAuthenticated ? (
          <Card className="border-[#f3b74f]/25 bg-[#101b22]/90">
            <CardContent className="p-6 sm:p-8">
              <div className="flex items-start gap-4">
                <Flag className="mt-1 h-6 w-6 shrink-0 text-[#ffd28a]" />
                <div>
                  <h2 className="text-lg font-semibold text-[#f4fbf8]">
                    Sign in to submit a report
                  </h2>
                  <p className="mt-2 text-sm leading-6 text-[#c1cfcb]">
                    Scanning stays open to everyone, but reports are tied to an
                    account to reduce duplicates and abuse.
                  </p>
                  <Button
                    onClick={() => startLogin()}
                    className="mt-5 bg-[#8df0b8] font-semibold text-[#09130f] hover:bg-[#b0f7cd]"
                  >
                    Sign in to continue
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-white/10 bg-[#101b22]/90">
            <CardHeader>
              <CardTitle className="text-xl text-[#f4fbf8]">
                What did you notice?
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={submit} className="space-y-5">
                <div>
                  <label
                    htmlFor="report-url"
                    className="mb-2 block text-sm font-medium text-[#e0e9e6]"
                  >
                    Website URL
                  </label>
                  <Input
                    id="report-url"
                    required
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="h-12 border-white/10 bg-[#081018] text-[#f4fbf8] placeholder:text-[#8d9f9b] focus-visible:ring-[#8df0b8]"
                  />
                </div>
                <div>
                  <label
                    htmlFor="report-category"
                    className="mb-2 block text-sm font-medium text-[#e0e9e6]"
                  >
                    Category
                  </label>
                  <select
                    id="report-category"
                    value={category}
                    onChange={e =>
                      setCategory(e.target.value as (typeof categories)[number])
                    }
                    className="h-12 w-full rounded-md border border-white/10 bg-[#081018] px-3 text-sm text-[#f4fbf8] outline-none focus:border-[#8df0b8]"
                  >
                    {categories.map(item => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label
                    htmlFor="report-description"
                    className="mb-2 block text-sm font-medium text-[#e0e9e6]"
                  >
                    Description{" "}
                    <span className="font-normal text-[#9fb0ac]">
                      (optional)
                    </span>
                  </label>
                  <Textarea
                    id="report-description"
                    value={description}
                    maxLength={500}
                    onChange={e => setDescription(e.target.value)}
                    placeholder="What made the site look suspicious?"
                    className="min-h-28 border-white/10 bg-[#081018] text-[#f4fbf8] placeholder:text-[#8d9f9b] focus-visible:ring-[#8df0b8]"
                  />
                  <p className="mt-1 text-right text-[11px] text-[#9fb0ac]">
                    {description.length}/500
                  </p>
                </div>
                <div
                  aria-hidden="true"
                  className="absolute -left-[10000px] h-px w-px overflow-hidden"
                >
                  <label htmlFor="report-company">Company</label>
                  <input
                    id="report-company"
                    tabIndex={-1}
                    autoComplete="off"
                    value={honeypot}
                    onChange={e => setHoneypot(e.target.value)}
                  />
                </div>
                {report.error && (
                  <div
                    role="alert"
                    className="flex gap-3 rounded-xl border border-[#ff6b5f]/20 bg-[#ff6b5f]/[0.08] p-3 text-sm text-[#ffb4ab]"
                  >
                    <AlertTriangle className="h-4 w-4 shrink-0" />
                    {report.error.message}
                  </div>
                )}
                {report.data?.success && (
                  <div
                    role="status"
                    className="flex gap-3 rounded-xl border border-[#6ee7a5]/20 bg-[#6ee7a5]/[0.08] p-3 text-sm text-[#9bf3c1]"
                  >
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    Thanks. Your report was recorded as an unverified community
                    signal.
                  </div>
                )}
                <Button
                  type="submit"
                  disabled={report.isPending || report.data?.success}
                  className="w-full bg-[#8df0b8] font-semibold text-[#09130f] hover:bg-[#b0f7cd]"
                >
                  <Send className="mr-2 h-4 w-4" />
                  {report.isPending
                    ? "Submitting…"
                    : report.data?.success
                      ? "Report submitted"
                      : "Submit report"}
                </Button>
              </form>
            </CardContent>
          </Card>
        )}
        <p className="mt-6 text-xs leading-5 text-[#9fb0ac]">
          Please do not include passwords, payment details, or private personal
          information in your description.
        </p>
      </main>
    </div>
  );
}
