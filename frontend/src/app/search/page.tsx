"use client";
import { Suspense } from "react";
import { useEffect, useState, useRef } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { search as searchApi, type SearchResult } from "@/lib/api";

const typeIcon: Record<string, string> = {
  actor: "person_alert",
  entity: "fingerprint",
  event: "dynamic_feed",
  infra: "dns",
};

function SearchContent() {
  const sp = useSearchParams();
  const [query, setQuery] = useState(sp.get("q") ?? "");
  const [type, setType] = useState("all");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const doSearch = (q: string, t: string) => {
    if (!q.trim()) return;
    setLoading(true);
    searchApi.query(q, t !== "all" ? t : undefined)
      .then(setResults)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (query) doSearch(query, type);
    inputRef.current?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const grouped = {
    actor: results.filter((r) => r.type === "actor"),
    entity: results.filter((r) => r.type === "entity"),
    event: results.filter((r) => r.type === "event"),
    infra: results.filter((r) => r.type === "infra"),
  };

  return (
    <>
      {/* Header */}
      <div className="border-b border-mist pb-6 mb-8">
        <h1 className="font-headline-xl text-headline-xl text-graphite tracking-tight mb-1">Search</h1>
        <p className="font-body-caption text-ash">Query the full intelligence archive — actors, wallets, onions, PGP keys, IPs, and events</p>
      </div>

      {/* Hero search */}
      <div className="max-w-3xl mx-auto mb-8">
        <div className="relative bg-paper border border-mist rounded-full shadow-editorial h-12 flex items-center px-5 gap-3">
          <span className="material-symbols-outlined text-ash text-[20px]">search</span>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doSearch(query, type)}
            className="flex-1 bg-transparent border-none outline-none text-graphite font-body-default text-body-default placeholder:text-ash"
            placeholder="Search actors, wallets, onions, PGP keys, emails…"
          />
          <kbd className="font-code-compact text-code-compact bg-surface-container border border-mist px-1.5 rounded text-ash">⏎</kbd>
        </div>

        {/* Type filters */}
        <div className="flex items-center justify-center gap-2 mt-4">
          {["all", "actor", "entity", "event", "infra"].map((t) => (
            <button
              key={t}
              onClick={() => { setType(t); doSearch(query, t); }}
              className={`px-3 py-1 rounded-full text-label-ui font-label-ui capitalize border transition-colors ${
                type === t
                  ? "bg-primary-container text-paper border-primary-container"
                  : "border-mist text-ash hover:text-charcoal hover:bg-linen"
              }`}
            >
              {t === "all" ? "All" : t === "infra" ? "Infrastructure" : t.charAt(0).toUpperCase() + t.slice(1)}
              {type === t && results.length > 0 && ` (${t === "all" ? results.length : grouped[t as keyof typeof grouped]?.length ?? 0})`}
            </button>
          ))}
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="space-y-3 max-w-3xl mx-auto">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="bg-paper border border-mist rounded-xl p-4 animate-pulse">
              <div className="h-3 bg-linen rounded w-1/4 mb-2" />
              <div className="h-4 bg-linen rounded w-3/4 mb-2" />
              <div className="h-3 bg-linen rounded w-1/2" />
            </div>
          ))}
        </div>
      )}

      {/* Results */}
      {!loading && results.length > 0 && (
        <div className="max-w-3xl mx-auto space-y-8">
          {(["actor", "entity", "event", "infra"] as const).map((t) => {
            const group = grouped[t];
            if (type !== "all" && type !== t) return null;
            if (group.length === 0) return null;
            return (
              <div key={t}>
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-ash text-[18px]">{typeIcon[t]}</span>
                  <h2 className="font-headline-lg text-headline-lg text-graphite">{t.charAt(0).toUpperCase() + t.slice(1)}s</h2>
                  <span className="font-code-compact text-code-compact text-ash">({group.length})</span>
                </div>
                <div className="space-y-3">
                  {group.map((r) => (
                    <div key={r.id} className="bg-paper border border-mist rounded-xl p-4 shadow-editorial hover:shadow-diagram transition-shadow cursor-pointer">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-[10px] font-label-uppercase border border-mist px-2 py-0.5 rounded text-charcoal capitalize">{r.type}</span>
                            <span className="text-[11px] font-body-caption text-ash">{r.source}</span>
                          </div>
                          <p className="font-body-emphasis text-body-default text-ink-black truncate">{r.primary}</p>
                          <p className="font-body-caption text-body-caption text-ash mt-0.5 line-clamp-2">{r.snippet}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <span className="font-code-compact text-code-compact text-ash text-[11px]">{r.date?.slice(0, 10) ?? ""}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Empty */}
      {!loading && query && results.length === 0 && (
        <div className="text-center py-20">
          <span className="material-symbols-outlined text-[48px] text-fog mb-4">search_off</span>
          <h3 className="font-headline-xl text-headline-xl text-graphite">No Results</h3>
          <p className="font-body-reading text-ash mt-2">Try a different query or broaden the type filter.</p>
        </div>
      )}

      {/* Initial state */}
      {!loading && !query && (
        <div className="text-center py-20">
          <span className="material-symbols-outlined text-[48px] text-fog mb-4">manage_search</span>
          <h3 className="font-headline-xl text-headline-xl text-graphite">Intelligence Archive</h3>
          <p className="font-body-reading text-ash mt-2">Enter a query to search across the full threat database.</p>
          <div className="flex flex-wrap items-center justify-center gap-2 mt-6">
            {["LockBit", "1A1zP1…", "facebookwkhpilnemxj…onion", "3048…PGP", "185.220.101.0/24"].map((ex) => (
              <button key={ex} onClick={() => { setQuery(ex); doSearch(ex, type); }}
                className="px-3 py-1.5 rounded-full border border-mist text-label-ui font-label-ui text-charcoal hover:bg-linen hover:text-ink-black transition-colors font-code-compact text-[12px]">
                {ex}
              </button>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

export default function SearchPage() {
  return (
    <AppLayout>
      <Suspense fallback={
        <div className="flex items-center justify-center py-32">
          <span className="font-body-caption text-ash">Loading search…</span>
        </div>
      }>
        <SearchContent />
      </Suspense>
    </AppLayout>
  );
}
