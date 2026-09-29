"use client";
import { useEffect, useState } from "react";
import AppLayout from "@/components/AppLayout";
import { actors, alertsApi, pipeline, type Actor, type Alert, type SourceHealth } from "@/lib/api";
import { useWebSocket } from "@/lib/useWebSocket";
import Link from "next/link";

interface FeedEntry {
  id: string;
  timestamp: string;
  source: string;
  title?: string;
  severity?: string;
  entities_found?: number;
  entity_kinds?: string[];
}

const statusDot: Record<string, string> = {
  online: "bg-status-live",
  degraded: "bg-status-warn",
  offline: "bg-status-error",
};

const statusText: Record<string, string> = {
  online: "text-status-live",
  degraded: "text-status-warn",
  offline: "text-status-error",
};

const statusBadge: Record<string, string> = {
  online: "bg-green-50 border-green-200 text-status-live",
  degraded: "bg-amber-50 border-amber-200 text-status-warn",
  offline: "bg-red-50 border-red-200 text-status-error",
};

export default function DashboardPage() {
  const [actorCount, setActorCount] = useState<number>(0);
  const [activeCount, setActiveCount] = useState<number>(0);
  const [events24h, setEvents24h] = useState<number>(0);
  const [unreadAlerts, setUnreadAlerts] = useState<Alert[]>([]);
  const [sources, setSources] = useState<SourceHealth[]>([]);
  const [feed, setFeed] = useState<FeedEntry[]>([]);
  const [clock, setClock] = useState<string>("");

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setClock(`${now.toISOString().slice(0, 10)} · ${now.toUTCString().slice(17, 25)} UTC`);
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);

    actors.list({ page: 1, page_size: 1 }).then((r) => {
      setActorCount(r.total);
      setActiveCount(r.items.filter((a) => a.status === "active").length);
    }).catch(() => {});
    alertsApi.list({ unread: "true", limit: "5" }).then((r) => {
      if (r && Array.isArray(r.items)) {
        setUnreadAlerts(r.items);
      } else if (Array.isArray(r)) {
        setUnreadAlerts(r);
      } else {
        setUnreadAlerts([]);
      }
    }).catch(() => setUnreadAlerts([]));
    pipeline.health().then((s) => {
      if (Array.isArray(s)) setSources(s);
    }).catch(() => {});
    pipeline.metrics().then((m) => {
      if (m && typeof m.events_24h === "number") setEvents24h(m.events_24h);
    }).catch(() => {});

    pipeline.liveEvents(20).then((r) => {
      if (r && Array.isArray(r.events) && r.events.length > 0) {
        const entries: FeedEntry[] = r.events.map((e) => ({
          id: crypto.randomUUID(),
          timestamp: e.timestamp,
          source: e.source,
          title: e.title,
          severity: e.severity,
          entities_found: e.entities_found,
        }));
        setFeed(entries);
      }
    }).catch(() => {});

    return () => clearInterval(timer);
  }, []);

  useWebSocket((msg) => {
    if (msg.channel === "events" && msg.data) {
      const entry = msg.data as FeedEntry;
      setFeed((prev) => {
        const key = `${entry.source}:${entry.title}`;
        const isDupe = prev.some((e) => `${e.source}:${e.title}` === key);
        if (isDupe) return prev;
        return [{ ...entry, id: crypto.randomUUID(), timestamp: entry.timestamp || new Date().toISOString() }, ...prev.slice(0, 49)];
      });
    }
  }, ["events"]);

  const severityBorder: Record<string, string> = {
    critical: "border-l-severity-critical",
    high: "border-l-severity-high",
    medium: "border-l-severity-medium",
    low: "border-l-severity-low",
  };

  const severityBadge: Record<string, string> = {
    critical: "bg-red-50 text-severity-critical border border-red-200",
    high: "bg-orange-50 text-severity-high border border-orange-200",
    medium: "bg-amber-50 text-severity-medium border border-amber-200",
    low: "bg-green-50 text-severity-low border border-green-200",
  };

  const safeAlerts = Array.isArray(unreadAlerts) ? unreadAlerts : [];

  const statCards = [
    {
      label: "Actors Tracked",
      value: actorCount,
      icon: "groups",
      trend: "+3 this month",
      trendCls: "text-status-live",
      trendIcon: "trending_up",
      sub: "5 advanced persistent campaigns",
      accent: "border-t-2 border-t-cerulean",
    },
    {
      label: "Active Groups",
      value: activeCount,
      icon: "deployed_code",
      trend: "High syndicate posture",
      trendCls: "text-status-warn",
      trendIcon: "warning",
      sub: "Cluster delta: 0 net closures",
      accent: "border-t-2 border-t-status-warn",
    },
    {
      label: "Events (24h)",
      value: (events24h ?? 0).toLocaleString(),
      icon: "dynamic_feed",
      trend: "Live ingesting",
      trendCls: "text-cerulean",
      trendIcon: "radio_button_checked",
      sub: "Normalized across all sources",
      accent: "border-t-2 border-t-signal-blue",
    },
    {
      label: "Unread Alerts",
      value: safeAlerts.length,
      icon: "crisis_alert",
      trend: `${safeAlerts.filter(a => a?.severity === "critical").length} critical`,
      trendCls: "text-severity-critical",
      trendIcon: "priority_high",
      sub: "Immediate triage mandated",
      accent: "border-t-2 border-t-severity-critical",
      valueCls: "text-severity-critical",
    },
  ];

  return (
    <AppLayout>
      {/* ── Page header ─────────────────────────────── */}
      <div className="mb-8">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 pb-6 border-b border-mist">
          <div className="space-y-2">
            {/* Breadcrumb / classification row */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-surface-container border border-mist text-ash text-[11px] font-code-compact">
                <span className="w-1.5 h-1.5 rounded-full bg-status-live" />
                DS-ID: 2025-05-89X
              </span>
              <span className="text-fog text-[11px]">/</span>
              <span className="text-ash text-[12px] font-body-caption">Compartment Alpha-Seven</span>
            </div>

            {/* Title */}
            <h1 className="text-[32px] leading-tight font-bold text-graphite tracking-tight" style={{ fontFamily: "Fraunces, serif", fontWeight: 500 }}>
              Overview
            </h1>
            <p className="text-ash text-[14px] leading-relaxed max-w-md">
              Operational Threat Intelligence & Disruption Summary
            </p>
          </div>

          {/* Clock + status */}
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-2 px-3 py-2 bg-paper border border-mist rounded-lg shadow-sm">
              <span className="material-symbols-outlined text-ash text-[15px]">schedule</span>
              <span className="text-[12px] font-code-compact text-charcoal">{clock || "—"}</span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-50 border border-green-200">
              <span className="w-1.5 h-1.5 rounded-full bg-status-live animate-pulse" />
              <span className="text-[11px] font-label-uppercase text-status-live">All Systems Nominal</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Stat cards ──────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5 mb-10">
        {statCards.map((card) => (
          <div key={card.label} className={`bg-paper rounded-xl border border-mist shadow-sm overflow-hidden ${card.accent}`}>
            <div className="p-5">
              {/* Label + icon */}
              <div className="flex items-center justify-between mb-4">
                <span className="text-[11px] font-label-uppercase text-ash tracking-wider">{card.label}</span>
                <div className="w-8 h-8 rounded-lg bg-surface-container flex items-center justify-center">
                  <span className="material-symbols-outlined text-charcoal text-[17px]">{card.icon}</span>
                </div>
              </div>

              {/* Value */}
              <div className={`text-[36px] leading-none font-bold tracking-tight mb-3 ${card.valueCls ?? "text-graphite"}`} style={{ fontFamily: "Fraunces, serif", fontWeight: 500 }}>
                {card.value}
              </div>

              {/* Trend pill */}
              <div className="flex items-center gap-1.5 mb-3">
                <span className={`material-symbols-outlined text-[13px] ${card.trendCls}`}>{card.trendIcon}</span>
                <span className={`text-[12px] font-medium ${card.trendCls}`}>{card.trend}</span>
              </div>

              {/* Sub-label */}
              <div className="pt-3 border-t border-mist">
                <p className="text-[12px] text-ash leading-snug">{card.sub}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── 2-column content grid ───────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

        {/* Left col — 8/12 */}
        <div className="lg:col-span-8 space-y-8">

          {/* Source health */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-[20px] font-semibold text-graphite tracking-tight" style={{ fontFamily: "Fraunces, serif", fontWeight: 400 }}>
                  Source Status
                </h2>
                <p className="text-[13px] text-ash mt-0.5">Health telemetry across primary crawler nodes</p>
              </div>
              <button
                onClick={() => pipeline.health().then((s) => { if (Array.isArray(s)) setSources(s); }).catch(() => {})}
                className="inline-flex items-center gap-1.5 text-[13px] font-medium text-charcoal hover:text-cerulean transition-colors px-3 py-1.5 rounded-lg hover:bg-linen border border-transparent hover:border-mist"
              >
                <span className="material-symbols-outlined text-[15px]">refresh</span>
                <span>Poll All</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {!Array.isArray(sources) || sources.length === 0 ? (
                Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="bg-paper border border-mist rounded-xl p-4 animate-pulse">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-2 h-2 rounded-full bg-linen" />
                      <div className="h-3 bg-linen rounded w-3/4" />
                    </div>
                    <div className="h-2.5 bg-linen rounded w-1/2 mb-1.5" />
                    <div className="h-2 bg-linen rounded w-1/3" />
                  </div>
                ))
              ) : sources.map((src) => (
                <div key={src.name} className="bg-paper border border-mist rounded-xl p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-start justify-between mb-3">
                    <span className="text-[13px] font-semibold text-graphite leading-snug flex-1 min-w-0 mr-2 truncate">{src.name}</span>
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border shrink-0 ${statusBadge[src.status] ?? "bg-linen border-mist text-ash"}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${statusDot[src.status] ?? "bg-fog"}`} />
                      {src.status}
                    </span>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[11px] text-ash">
                      {src.last_success ? `Last run: ${new Date(src.last_success).toLocaleTimeString()}` : "Not yet run"}
                    </div>
                    <div className="text-[12px] font-semibold text-charcoal font-mono">
                      {src.events_24h.toLocaleString()} events / 24h
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Recent alerts */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-[20px] font-semibold text-graphite tracking-tight" style={{ fontFamily: "Fraunces, serif", fontWeight: 400 }}>
                  Recent Alerts
                </h2>
                <p className="text-[13px] text-ash mt-0.5">Unread threat alerts requiring attention</p>
              </div>
              <Link href="/alerts" className="inline-flex items-center gap-1 text-[13px] font-medium text-cerulean hover:opacity-80 transition-opacity">
                View all
                <span className="material-symbols-outlined text-[15px]">arrow_forward</span>
              </Link>
            </div>

            <div className="space-y-3">
              {safeAlerts.length === 0 ? (
                <div className="bg-paper border border-mist rounded-xl p-8 text-center">
                  <span className="material-symbols-outlined text-fog text-[32px] mb-2 block">check_circle</span>
                  <p className="text-[14px] text-ash">No active threat alerts matching current filters.</p>
                </div>
              ) : safeAlerts.map((a) => (
                <div key={a.id} className={`bg-paper border border-mist rounded-xl p-4 border-l-4 hover:shadow-sm transition-shadow ${severityBorder[a.severity] ?? "border-l-fog"}`}>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className={`text-[10px] font-bold tracking-widest px-2 py-0.5 rounded ${severityBadge[a.severity] ?? "bg-linen text-ash border border-mist"}`}>
                          {a.severity?.toUpperCase()}
                        </span>
                        {a.actor_handle && (
                          <Link href={`/actors/${a.actor_id}`} className="text-[12px] font-medium text-cerulean hover:opacity-80 inline-flex items-center gap-0.5">
                            <span className="material-symbols-outlined text-[13px]">person</span>
                            {a.actor_handle}
                          </Link>
                        )}
                      </div>
                      <p className="text-[14px] font-semibold text-graphite mb-0.5 line-clamp-1">{a.title}</p>
                      <p className="text-[13px] text-ash line-clamp-1">{a.body}</p>
                    </div>
                    <Link href="/alerts" className="text-cerulean hover:opacity-80 shrink-0 p-1 rounded hover:bg-linen transition-colors">
                      <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Right col — 4/12 */}
        <div className="lg:col-span-4 space-y-5">

          {/* Live feed */}
          <div className="bg-paper border border-mist rounded-xl shadow-sm overflow-hidden flex flex-col" style={{ height: 440 }}>
            {/* Feed header */}
            <div className="px-4 py-3 border-b border-mist flex items-center justify-between shrink-0 bg-linen">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-status-live animate-pulse" />
                <span className="text-[13px] font-semibold text-graphite">Live Feed</span>
              </div>
              <span className="text-[10px] font-code-compact text-ash bg-surface-container px-2 py-0.5 rounded border border-mist">ws://feed</span>
            </div>

            {/* Feed entries */}
            <div className="flex-1 overflow-y-auto p-3 space-y-0">
              {feed.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-center">
                  <span className="material-symbols-outlined text-fog text-[28px] mb-2">wifi_tethering</span>
                  <p className="text-[13px] text-ash">Waiting for events…</p>
                </div>
              ) : feed.map((ev) => (
                <div key={ev.id} className="py-2.5 border-b border-mist/50 last:border-0">
                  <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                    <span className="text-[10px] font-mono text-fog">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="bg-surface-container border border-mist px-1.5 py-0.5 rounded text-[10px] font-medium text-charcoal">
                      {ev.source}
                    </span>
                    {ev.severity && ev.severity !== "info" && (
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        ev.severity === "critical" ? "bg-red-50 text-severity-critical" :
                        ev.severity === "warning" ? "bg-amber-50 text-severity-medium" :
                        "bg-linen text-ash"
                      }`}>{ev.severity}</span>
                    )}
                  </div>
                  {ev.title ? (
                    <p className="text-[12px] text-graphite leading-snug">{ev.title}</p>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {ev.entity_kinds?.map((k) => (
                        <span key={k} className="text-[10px] bg-linen border border-mist text-ash px-1.5 py-0.5 rounded">{k}</span>
                      ))}
                    </div>
                  )}
                  {ev.entities_found != null && ev.entities_found > 0 && (
                    <span className="text-[11px] font-mono text-cerulean mt-0.5 inline-block">
                      {ev.entities_found.toLocaleString()} items
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Quick actions */}
          <div className="bg-paper border border-mist rounded-xl shadow-sm overflow-hidden">
            <div className="px-4 py-3 border-b border-mist bg-linen">
              <h3 className="text-[13px] font-semibold text-graphite">Quick Actions</h3>
            </div>
            <div className="p-2">
              {[
                { label: "Run Graph Analytics", icon: "hub", href: "/pipeline", desc: "Process intel graph" },
                { label: "Browse All Actors", icon: "person_alert", href: "/actors", desc: "Actor registry" },
                { label: "Search Intelligence", icon: "search", href: "/search", desc: "Query the archive" },
                { label: "Triage Alerts", icon: "notifications_active", href: "/alerts", desc: "Review unread alerts" },
              ].map((action) => (
                <Link key={action.label} href={action.href}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-linen transition-colors group"
                >
                  <div className="w-7 h-7 rounded-lg bg-surface-container flex items-center justify-center shrink-0 group-hover:bg-surface-container-high transition-colors">
                    <span className="material-symbols-outlined text-charcoal text-[15px]">{action.icon}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-[13px] font-medium text-graphite leading-tight">{action.label}</div>
                    <div className="text-[11px] text-ash">{action.desc}</div>
                  </div>
                  <span className="material-symbols-outlined text-fog text-[15px] group-hover:text-charcoal transition-colors">arrow_forward</span>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
