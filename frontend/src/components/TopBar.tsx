"use client";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { clearToken, exports_ as exportsApi } from "@/lib/api";

interface TopBarProps {
  alertCount?: number;
}

export default function TopBar({ alertCount = 0 }: TopBarProps) {
  const router = useRouter();

  const handleLogout = () => {
    clearToken();
    router.push("/login");
  };

  return (
    <header className="sticky top-0 z-40 w-full h-16 bg-paper border-b border-mist flex items-center justify-between px-space-lg">
      {/* Left: Brand + Classification */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-graphite text-[22px]">policy</span>
          <Link href="/dashboard" className="font-headline-lg text-[20px] font-normal text-graphite tracking-tight hover:text-ink-black transition-colors">
            NETRA
          </Link>
        </div>
        <div className="h-4 w-[1px] bg-mist" />
        <span className="bg-surface-container-low text-ash border border-mist px-2 py-0.5 rounded text-[10px] font-label-uppercase tracking-[0.08em] font-semibold select-none">
          CLASSIFIED // REL TO INTEL
        </span>
      </div>

      {/* Center: Search */}
      <div className="w-full max-w-xs md:max-w-md hidden md:flex items-center">
        <div className="relative w-full">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-ash text-[18px]">search</span>
          <input
            className="w-full bg-linen border-0 border-b border-charcoal/40 text-graphite placeholder:text-ash text-body-default font-body-default pl-9 pr-10 py-1.5 focus:outline-none focus:ring-0 focus:border-b-2 focus:border-graphite transition-all"
            placeholder="Search actors, wallets, onions…"
            type="text"
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                const val = (e.target as HTMLInputElement).value.trim();
                if (val) router.push(`/search?q=${encodeURIComponent(val)}`);
              }
            }}
          />
          <div className="absolute right-2 top-1/2 -translate-y-1/2">
            <kbd className="px-1.5 py-0.5 text-[10px] font-code-compact bg-paper border border-mist text-ash rounded">⌘K</kbd>
          </div>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-space-md">
        {/* Export Intel */}
        <button
          onClick={() => exportsApi.intel('json').catch((e: Error) => alert('Export failed: ' + e.message))}
          className="hidden lg:inline-flex items-center gap-1.5 px-3 py-1.5 text-label-ui font-label-ui border border-cerulean text-cerulean rounded-lg hover:opacity-80 transition-opacity"
        >
          <span className="material-symbols-outlined text-[16px]">ios_share</span>
          <span>Export Intel</span>
        </button>

        {/* Notification Bell */}
        <Link href="/alerts" className="relative cursor-pointer p-1.5 rounded-lg hover:bg-linen text-graphite transition-colors">
          <span className="material-symbols-outlined text-[20px]">notifications</span>
          {alertCount > 0 && (
            <span className="absolute top-1 right-1 flex items-center justify-center bg-primary-container text-paper text-[10px] font-mono font-medium rounded-full min-w-[15px] h-[15px] px-0.5">
              {alertCount}
            </span>
          )}
        </Link>

        {/* Live Node Status */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 bg-surface-container-low border border-mist rounded-full">
          <span className="w-1.5 h-1.5 rounded-full bg-status-live animate-pulse" />
          <span className="text-label-uppercase font-label-uppercase text-ash text-[11px]">LIVE NODE</span>
        </div>

        {/* User */}
        <div
          className="flex items-center gap-2 pl-2 border-l border-mist cursor-pointer group"
          onClick={handleLogout}
        >
          <div className="w-8 h-8 rounded-full border border-mist bg-surface-container flex items-center justify-center text-charcoal font-label-ui text-label-ui font-semibold">
            AV
          </div>
          <div className="hidden xl:flex flex-col text-left">
            <span className="text-label-ui font-label-ui text-ink-black leading-tight group-hover:text-cerulean transition-colors">A. Vance</span>
            <span className="text-[10px] font-body-caption text-ash">Dir. Forensic Dossier</span>
          </div>
          <span className="material-symbols-outlined text-ash text-[18px] group-hover:text-ink-black transition-colors">expand_more</span>
        </div>
      </div>
    </header>
  );
}
