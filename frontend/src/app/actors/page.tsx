"use client";
import { useEffect, useState } from "react";
import AppLayout from "@/components/AppLayout";
import { actors as actorsApi, exports_ as exportsApi, type Actor, type ActorsResponse } from "@/lib/api";
import Link from "next/link";

const confidenceColor: Record<string, string> = {
  A: "text-confidence-high",
  B: "text-confidence-med",
  C: "text-confidence-low",
  D: "text-ash",
  E: "text-fog",
};

const statusDot: Record<string, string> = {
  active: "bg-status-live",
  dormant: "bg-status-warn",
  defunct: "bg-fog",
};

export default function ActorsPage() {
  const [data, setData] = useState<ActorsResponse | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string | number> = { page, page_size: 20 };
    if (search) params.search = search;
    if (status !== "all") params.status = status;
    actorsApi.list(params).then(setData).catch(() => {}).finally(() => setLoading(false));
  }, [search, status, page]);

  const totalPages = data ? Math.ceil(data.total / 20) : 1;
  const items = Array.isArray(data?.items) ? data.items : [];
  const total = data?.total ?? 0;

  return (
    <AppLayout>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-6 border-b border-mist pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-code-compact text-code-compact text-ash tracking-widest uppercase">REGISTRY / ARCHIVE_SEC_04</span>
            <span className="text-mist">/</span>
            <span className="font-code-compact text-code-compact text-cerulean">{total} ENTITIES ACTIVE</span>
          </div>
          <h1 className="font-headline-xl text-headline-xl text-ink-black tracking-tight">Actors</h1>
          <p className="font-body-reading text-charcoal text-body-caption mt-1">
            Classified Threat-Actor &amp; Syndicate Registry
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => exportsApi.batch('json').catch((e: Error) => alert('Export failed: ' + e.message))}
            className="border border-twilight text-twilight hover:bg-linen font-label-ui text-label-ui px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
          >
            <span className="material-symbols-outlined text-[16px]">file_download</span>
            <span>Batch Export</span>
          </button>
          <button className="border border-cerulean text-cerulean hover:opacity-80 font-label-ui text-label-ui px-4 py-2 rounded-lg flex items-center gap-2 transition-opacity">
            <span className="material-symbols-outlined text-[16px]">person_add</span>
            <span>+ Register Actor →</span>
          </button>
        </div>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        {[
          { label: "ACTIVE THREATS", value: items.filter(a => a.status === "active").length, dot: "bg-status-live" },
          { label: "UNDER OBSERVATION", value: items.filter(a => a.status === "dormant").length, dot: "bg-status-warn" },
          { label: "DORMANT / ARCHIVED", value: items.filter(a => a.status === "defunct").length, dot: "bg-fog" },
          { label: "CONFIDENCE BAND A", value: items.filter(a => a.confidence_band === "A").length, dot: "bg-confidence-high", valueCls: "text-confidence-high" },
        ].map((s) => (
          <div key={s.label} className="bg-paper border border-mist p-3 rounded-lg flex items-center justify-between shadow-card">
            <div className="flex flex-col">
              <span className="font-label-uppercase text-label-uppercase text-ash">{s.label}</span>
              <span className={`font-code-default text-headline-sub font-semibold mt-0.5 ${s.valueCls ?? "text-ink-black"}`}>{s.value}</span>
            </div>
            <span className={`w-2.5 h-2.5 rounded-full ${s.dot}`} />
          </div>
        ))}
      </div>

      {/* Search + Filter */}
      <div className="bg-paper border border-mist rounded-xl p-4 shadow-card mb-6">
        <div className="flex flex-col md:flex-row gap-4 items-start md:items-center">
          <div className="relative flex-1 max-w-md">
            <span className="material-symbols-outlined absolute left-0 top-1/2 -translate-y-1/2 text-ash text-[18px]">search</span>
            <input
              type="text"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="ledger-input w-full pl-7 py-1.5 text-body-default font-body-default text-graphite"
              placeholder="Search actor handles, aliases, categories…"
            />
          </div>
          <div className="flex items-center gap-2">
            {["all", "active", "dormant", "defunct"].map((s) => (
              <button
                key={s}
                onClick={() => { setStatus(s); setPage(1); }}
                className={`px-3 py-1.5 rounded-lg text-label-ui font-label-ui capitalize transition-colors ${
                  status === s
                    ? "bg-surface-container-low border border-mist text-ink-black font-semibold"
                    : "text-ash hover:text-ink-black hover:bg-linen"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-paper border border-mist rounded-xl shadow-editorial overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-mist">
              {["Handle", "Category", "Status", "Confidence", "Entities", "First Seen", "Last Seen", ""].map((h) => (
                <th key={h} className="px-4 py-3 text-left text-[11px] font-label-uppercase text-ash tracking-[0.06em] uppercase">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-mist">
                  {Array.from({ length: 8 }).map((_, j) => (
                    <td key={j} className="px-4 py-3">
                      <div className="h-3 bg-linen rounded animate-pulse w-3/4" />
                    </td>
                  ))}
                </tr>
              ))
            ) : items.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-ash font-body-caption text-body-caption">
                  No actors match your filters.
                </td>
              </tr>
            ) : items.map((actor) => (
              <tr key={actor.id} className="border-b border-mist hover:bg-linen transition-colors duration-100 group">
                <td className="px-4 py-3">
                  <Link href={`/actors/${actor.id}`} className="font-body-emphasis text-body-default text-ink-black hover:text-cerulean transition-colors">
                    {actor.handle}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <span className="text-[11px] font-label-uppercase text-charcoal border border-mist px-2 py-0.5 rounded capitalize">
                    {actor.category}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <span className={`w-1.5 h-1.5 rounded-full ${statusDot[actor.status] ?? "bg-fog"}`} />
                    <span className="font-label-ui text-label-ui text-charcoal capitalize">{actor.status}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className={`font-code-default text-code-default font-semibold ${confidenceColor[actor.confidence_band] ?? "text-ash"}`}>
                    {actor.confidence_band} ({actor.confidence_score})
                  </span>
                </td>
                <td className="px-4 py-3 font-body-caption text-body-caption text-ash">
                  {actor.entity_count}
                </td>
                <td className="px-4 py-3 font-code-compact text-code-compact text-ash">
                  {actor.first_seen?.slice(0, 10) ?? "—"}
                </td>
                <td className="px-4 py-3 font-code-compact text-code-compact text-ash">
                  {actor.last_seen?.slice(0, 10) ?? "—"}
                </td>
                <td className="px-4 py-3">
                  <Link href={`/actors/${actor.id}`} className="text-ash group-hover:text-cerulean transition-colors font-label-ui text-label-ui flex items-center gap-1">
                    View <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-mist flex items-center justify-between">
            <span className="font-body-caption text-body-caption text-ash">
              Page {page} of {totalPages} · {data?.total} total
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="px-3 py-1.5 rounded-lg border border-twilight text-twilight font-label-ui text-label-ui hover:bg-linen disabled:opacity-40 transition-colors"
              >
                ← Previous
              </button>
              <button
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page === totalPages}
                className="px-3 py-1.5 rounded-lg border border-twilight text-twilight font-label-ui text-label-ui hover:bg-linen disabled:opacity-40 transition-colors"
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
