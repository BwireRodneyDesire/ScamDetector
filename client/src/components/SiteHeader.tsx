import { Button } from "@/components/ui/button";
import { startLogin } from "@/const";
import { useAuth } from "@/_core/hooks/useAuth";
import { Radar } from "lucide-react";

export default function SiteHeader() {
  const { user, isAuthenticated, loading, logout } = useAuth();
  return (
    <header className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-7 lg:px-10">
      <a
        href="/"
        className="flex min-w-0 items-center gap-3"
        aria-label="PhishGuard home"
      >
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#6ee7a5]/30 bg-[#6ee7a5]/10 text-[#8df0b8]">
          <Radar className="h-5 w-5" />
        </span>
        <span className="min-w-0">
          <span className="block truncate font-mono text-[10px] uppercase tracking-[0.28em] text-[#8df0b8]">
            Makerere research prototype
          </span>
          <span className="block text-lg font-semibold tracking-tight text-[#edf5f2]">
            PhishGuard
          </span>
        </span>
      </a>
      <nav
        className="order-3 flex w-full flex-wrap items-center gap-x-4 gap-y-2 text-xs text-[#c1cfcb] sm:order-2 sm:w-auto"
        aria-label="Primary navigation"
      >
        <a href="/#scan" className="transition hover:text-[#8df0b8]">
          Scan
        </a>
        <a href="/report" className="transition hover:text-[#8df0b8]">
          Report a scam
        </a>
        <a href="/quiz" className="transition hover:text-[#8df0b8]">
          Test yourself
        </a>
        <a href="/#about" className="transition hover:text-[#8df0b8]">
          About
        </a>
      </nav>
      <div className="order-2 flex items-center gap-3 text-xs text-[#c1cfcb] sm:order-3">
        <span className="hidden items-center gap-2 lg:flex">
          <span className="h-2 w-2 animate-pulse rounded-full bg-[#6ee7a5]" />{" "}
          Live inspection engine
        </span>
        {loading ? (
          <span className="text-[#9fb0ac]">Checking account…</span>
        ) : isAuthenticated ? (
          <>
            <span className="hidden text-[#9bf3c1] md:inline">
              {user?.name || user?.email || "Signed in"}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void logout()}
              className="text-[#c1cfcb] hover:bg-white/5 hover:text-[#f4fbf8]"
            >
              Sign out
            </Button>
          </>
        ) : (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => startLogin()}
            className="border border-[#8df0b8]/25 text-[#9bf3c1] hover:bg-[#8df0b8]/10 hover:text-[#f4fbf8]"
          >
            Sign in
          </Button>
        )}
      </div>
    </header>
  );
}
