"use client";
import { useEffect, useState } from "react";
import { use } from "react";
import AppLayout from "@/components/AppLayout";
import {
  actors as actorsApi, timeline as timelineApi, infra as infraApi,
  exports_ as exportsApi, watchlist as watchlistApi,
  type Actor, type TimelineEvent, type InfraRecord, type Entity, type RebrandLink,
} from "@/lib/api";
import Link from "next/link";

type Tab = "entities" | "timeline" | "infrastructure" | "rebrand" | "evidence";

const confidenceColor: Record<string, string> = {
  A: "text-confidence-high", B: "text-confidence-med",
  C: "text-confidence-low", D: "text-ash", E: "text-fog",
};

export default function ActorDossierPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [actor, setActor] = useState<Actor | null>(null);
  const [tab, setTab] = useState<Tab>("entities");
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [infraList, setInfraList] = useState<InfraRecord[]>([]);
  const [links, setLinks] = useState<RebrandLink[]>([]);
  const [notes, setNotes] = useState("");
  const [loading, setLoading] = useState(true);
  const [exportLoading, setExportLoading] = useState(false);
  const [watchlisted, setWatchlisted] = useState(false);

  useEffect(() => {
    actorsApi.get(id).then((a) => { setActor(a); setNotes(a.notes ?? ""); }).catch(() => {}).finally(() => setLoading(false));
    timelineApi.get(id).then(setEvents).catch(() => {});
    infraApi.get(id).then(setInfraList).catch(() => {});
    actorsApi.links(id).then(setLinks).catch(() => {});
  }, [id]);

  const saveNotes = () => {
    if (!actor) return;
    actorsApi.patch(id, { notes }).catch(() => {});
  };

  const tabs: { key: Tab; label: string; icon: string }[] = [
    { key: "entities", label: "Entities", icon: "category" },
    { key: "timeline", label: "Timeline", icon: "timeline" },
    { key: "infrastructure", label: "Infrastructure", icon: "dns" },
    { key: "rebrand", label: "Rebrand Links", icon: "sync_alt" },
    { key: "evidence", label: "Evidence", icon: "verified" },
  ];

  if (loading) {
    return (
      <AppLayout>
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-20 bg-linen rounded-xl animate-pulse" />
          ))}
        </div>
      </AppLayout>
    );
  }

  if (!actor) {
    return (
      <AppLayout>
        <div className="flex flex-col items-center justify-center py-32 text-center">
          <span className="material-symbols-outlined text-[48px] text-fog mb-4">person_search</span>
          <h2 className="font-headline-xl text-headline-xl text-graphite">Actor Not Found</h2>
          <p className="text-ash font-body-caption mt-2">No actor with ID <code className="font-code-default">{id}</code></p>
          <Link href="/actors" className="mt-6 border border-cerulean text-cerulean px-4 py-2 rounded-lg font-label-ui text-label-ui hover:opacity-80 transition-opacity">
            ← Back to Registry
          </Link>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="flex flex-col xl:flex-row gap-6">
        {/* Left: Identity panel */}
        <div className="xl:w-[260px] shrink-0 space-y-4">
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <div className="mb-4">
              <h1 className="font-headline-lg text-headline-lg text-graphite">{actor.handle}</h1>
              <div className="flex flex-wrap gap-2 mt-2">
                <span className="text-[11px] font-label-uppercase border border-mist px-2 py-0.5 rounded text-charcoal capitalize">{actor.category}</span>
                <span className={`text-[11px] font-label-uppercase border px-2 py-0.5 rounded ${
                  actor.status === "active" ? "border-status-live text-status-live" :
                  actor.status === "dormant" ? "border-status-warn text-status-warn" :
                  "border-fog text-fog"
                } capitalize`}>{actor.status}</span>
              </div>
            </div>
            <div className="h-[1px] bg-mist my-4" />
            <div className="space-y-3">
              <div>
                <span className="text-[10px] font-label-uppercase text-ash tracking-wider">CONFIDENCE</span>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`font-headline-sub text-headline-sub font-bold ${confidenceColor[actor.confidence_band]}`}>
                    {actor.confidence_band}
                  </span>
                  <span className="font-code-default text-code-default text-ash">{actor.confidence_score}/100</span>
                </div>
                <div className="mt-2 h-1 bg-mist rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${actor.confidence_score >= 70 ? "bg-confidence-high" : actor.confidence_score >= 40 ? "bg-confidence-med" : "bg-confidence-low"}`}
                    style={{ width: `${actor.confidence_score}%` }} />
                </div>
              </div>
              <div className="h-[1px] bg-mist" />
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-[10px] font-label-uppercase text-ash tracking-wider">FIRST SEEN</span>
                  <p className="font-code-compact text-code-compact text-charcoal mt-0.5">{actor.first_seen?.slice(0, 10) ?? "—"}</p>
                </div>
                <div>
                  <span className="text-[10px] font-label-uppercase text-ash tracking-wider">LAST SEEN</span>
                  <p className="font-code-compact text-code-compact text-charcoal mt-0.5">{actor.last_seen?.slice(0, 10) ?? "—"}</p>
                </div>
              </div>
              <div className="h-[1px] bg-mist" />
              <div>
                <span className="text-[10px] font-label-uppercase text-ash tracking-wider">ANALYST NOTES</span>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  onBlur={saveNotes}
                  rows={4}
                  className="ledger-input w-full mt-1 py-1 text-body-reading font-body-reading text-charcoal resize-none"
                  placeholder="Add notes…"
                />
              </div>
            </div>
            <div className="h-[1px] bg-mist my-4" />
            <div className="space-y-2">
              <button
                onClick={() => { if (actor) watchlistApi.add(actor.id).then(() => setWatchlisted(true)).catch(() => {}); }}
                disabled={watchlisted}
                className={`w-full border font-label-ui text-label-ui py-2 px-3 rounded-lg flex items-center justify-center gap-1.5 transition-colors ${
                  watchlisted ? 'border-status-live text-status-live bg-linen' : 'border-twilight text-twilight hover:bg-linen'
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">{watchlisted ? 'bookmark_added' : 'bookmark_add'}</span>
                {watchlisted ? 'Watchlisted ✓' : 'Add to Watchlist'}
              </button>
              <button
                onClick={async () => {
                  if (!actor) return;
                  setExportLoading(true);
                  try { await exportsApi.dossier(actor.id, 'pdf'); } catch (e) { console.error('Export failed:', e); }
                  setExportLoading(false);
                }}
                disabled={exportLoading}
                className="w-full border border-cerulean text-cerulean hover:opacity-80 font-label-ui text-label-ui py-2 px-3 rounded-lg flex items-center justify-center gap-1.5 transition-opacity disabled:opacity-50"
              >
                <span className="material-symbols-outlined text-[16px]">{exportLoading ? 'hourglass_empty' : 'ios_share'}</span>
                {exportLoading ? 'Generating…' : 'Export Dossier →'}
              </button>
            </div>
          </div>

          {/* Entity count card */}
          <div className="bg-paper border border-mist rounded-xl p-4 shadow-diagram">
            <span className="text-[10px] font-label-uppercase text-ash tracking-wider">ENTITY COUNT</span>
            <div className="font-headline-sub text-headline-sub text-graphite font-bold mt-1">{actor.entity_count}</div>
            <p className="font-body-caption text-body-caption text-ash mt-0.5">Linked identifiers across all sources</p>
          </div>
        </div>

        {/* Main: tabs */}
        <div className="flex-1 min-w-0">
          {/* Tab nav */}
          <div className="flex items-center gap-0 border-b border-mist mb-6 overflow-x-auto">
            {tabs.map((t) => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`flex items-center gap-1.5 px-4 py-3 font-label-ui text-label-ui whitespace-nowrap transition-colors ${
                  tab === t.key
                    ? "text-ink-black border-b-2 border-twilight -mb-[1px]"
                    : "text-ash hover:text-charcoal"
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">{t.icon}</span>
                {t.label}
              </button>
            ))}
          </div>

          {/* Entities tab */}
          {tab === "entities" && (
            <div className="space-y-6">
              {[
                { icon: "🔑", label: "PGP KEYS", kind: "pgp" },
                { icon: "💰", label: "WALLETS", kind: "wallet" },
                { icon: "🧅", label: "ONION ADDRESSES", kind: "onion" },
                { icon: "📧", label: "EMAILS", kind: "email" },
                { icon: "📱", label: "CONTACT IDS", kind: "contact" },
                { icon: "🌐", label: "DOMAINS & IPS", kind: "domain" },
              ].map((group) => {
                const groupEntities = (actor.entities ?? []).filter((e: any) => {
                  const k = (e.kind || "").toLowerCase();
                  if (group.kind === "wallet") return k.includes("btc") || k.includes("wallet") || k.includes("crypto");
                  if (group.kind === "domain") return k.includes("domain") || k.includes("ip");
                  return k.includes(group.kind);
                });

                return (
                  <div key={group.kind}>
                    <div className="flex items-center gap-2 mb-3">
                      <span className="text-[16px]">{group.icon}</span>
                      <span className="text-[11px] font-label-uppercase text-ash tracking-widest">{group.label}</span>
                      <span className="text-[11px] font-code-compact text-ash">({groupEntities.length})</span>
                    </div>
                    <div className="bg-paper border border-mist rounded-xl overflow-hidden shadow-diagram">
                      {groupEntities.length === 0 ? (
                        <div className="px-4 py-3 text-center text-ash font-body-caption text-body-caption">
                          No {group.label.toLowerCase()} linked.
                        </div>
                      ) : (
                        groupEntities.map((e: any) => (
                          <div key={e.entity_id || e.value} className="px-4 py-3 flex items-center justify-between border-t border-mist first:border-0 hover:bg-linen transition-colors">
                            <span className="font-code-default text-body-default text-graphite font-medium">{e.value}</span>
                            <span className="text-[10px] font-label-uppercase bg-surface-container border border-mist text-ash px-2 py-0.5 rounded">{e.kind}</span>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Timeline tab */}
          {tab === "timeline" && (
            <div className="space-y-4">
              {events.length === 0 ? (
                <div className="text-center py-16 text-ash font-body-caption">No timeline events found.</div>
              ) : events.map((ev) => (
                <div key={ev.id} className="bg-paper border border-mist rounded-xl p-4 shadow-editorial">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="bg-surface-container border border-mist px-2 py-0.5 rounded text-[11px] font-label-ui text-charcoal">{ev.source}</span>
                    <span className="font-code-compact text-code-compact text-ash">{ev.occurred_at?.slice(0, 16)?.replace("T", " ")}</span>
                  </div>
                  <div className="flex flex-wrap gap-1 mb-2">
                    {ev.entity_kinds.map((k) => (
                      <span key={k} className="text-[10px] font-label-uppercase bg-linen border border-mist text-ash px-1.5 py-0.5 rounded">{k}</span>
                    ))}
                  </div>
                  <p className="font-body-reading text-body-reading text-charcoal line-clamp-2">{ev.snippet}</p>
                </div>
              ))}
            </div>
          )}

          {/* Infrastructure tab */}
          {tab === "infrastructure" && (
            <div className="bg-paper border border-mist rounded-xl overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-mist">
                    {["Onion URL", "Uptime", "Last Probed", "Clock Skew", "Favicon Hash", "Status"].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-[11px] font-label-uppercase text-ash tracking-[0.06em]">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {infraList.length === 0 ? (
                    <tr><td colSpan={6} className="px-4 py-12 text-center text-ash font-body-caption">No infrastructure data.</td></tr>
                  ) : infraList.map((rec) => (
                    <tr key={rec.id} className="border-b border-mist hover:bg-linen transition-colors">
                      <td className="px-4 py-3 font-code-default text-code-default text-charcoal max-w-[200px] truncate">{rec.onion_url}</td>
                      <td className="px-4 py-3 font-code-default text-code-default text-ash">{rec.uptime_pct.toFixed(1)}%</td>
                      <td className="px-4 py-3 font-code-compact text-code-compact text-ash">{rec.last_probed?.slice(0, 16)?.replace("T", " ") ?? "—"}</td>
                      <td className="px-4 py-3 font-code-compact text-code-compact text-ash">{rec.clock_skew_ms != null ? `${rec.clock_skew_ms}ms` : "—"}</td>
                      <td className="px-4 py-3 font-code-compact text-code-compact text-ash truncate max-w-[120px]">{rec.favicon_hash ?? "—"}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${rec.status === "up" ? "bg-status-live" : rec.status === "down" ? "bg-status-error" : "bg-fog"}`} />
                          <span className="text-[11px] font-label-ui text-ash capitalize">{rec.status}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Rebrand tab */}
          {tab === "rebrand" && (
            <div className="bg-paper border border-mist rounded-xl overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-mist">
                    {["Old Actor", "New Actor", "Score", "Shared Signals", "Detected"].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-[11px] font-label-uppercase text-ash tracking-[0.06em]">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {links.length === 0 ? (
                    <tr><td colSpan={5} className="px-4 py-12 text-center text-ash font-body-caption">No rebrand links detected.</td></tr>
                  ) : links.map((l) => (
                    <tr key={l.id} className="border-b border-mist hover:bg-linen transition-colors">
                      <td className="px-4 py-3"><Link href={`/actors/${l.old_actor.id}`} className="font-body-emphasis text-body-default text-cerulean hover:opacity-80">{l.old_actor.handle}</Link></td>
                      <td className="px-4 py-3"><Link href={`/actors/${l.new_actor.id}`} className="font-body-emphasis text-body-default text-cerulean hover:opacity-80">{l.new_actor.handle}</Link></td>
                      <td className="px-4 py-3">
                        <span className={`font-code-default text-code-default font-semibold ${l.score >= 70 ? "text-confidence-high" : l.score >= 40 ? "text-confidence-med" : "text-confidence-low"}`}>
                          {l.score}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {l.signals.map((s) => <span key={s} className="text-[10px] font-label-uppercase bg-linen border border-mist text-ash px-1.5 py-0.5 rounded">{s}</span>)}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-code-compact text-code-compact text-ash">{l.detected_at?.slice(0, 10) ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Evidence tab */}
          {tab === "evidence" && (
            <div className="space-y-3">
              <p className="text-ash font-body-caption text-body-caption">
                Provenance chain loaded per-event. Run collection to populate evidence records.
              </p>
              <div className="bg-paper border border-mist rounded-xl p-8 text-center">
                <span className="material-symbols-outlined text-[40px] text-fog mb-3">verified</span>
                <p className="font-body-reading text-ash">No evidence records. Trigger pipeline collection first.</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
