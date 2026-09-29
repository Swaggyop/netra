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

export default function DashboardPage() {
  const [actorCount, setActorCount] = useState<number>(0);
  const [activeCount, setActiveCount] = useState<number>(0);
  const [events24h, setEvents24h] = useState<number>(0);
  const [unreadAlerts, setUnreadAlerts] = useState<Alert[]>([]);
  const [sources, setSources] = useState<SourceHealth[]>([]);
  const [feed, setFeed] = useState<FeedEntry[]>([]);
  const [clock, setClock] = useState<string>("");

  useEffect(() => {
    // Set clock client-side only to avoid hydration mismatch
    const updateClock = () => {
      const now = new Date();
      setClock(`Cycle: ${now.toISOString().slice(0, 10)} · Node UTC ${now.toUTCString().slice(17, 25)}`);
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

    // Load real collected events from Redis into the Live Feed (initial load)
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
      // Deduplicate: skip if we already have an event with same source+title
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

  const safeAlerts = Array.isArray(unreadAlerts) ? unreadAlerts : [];

  return (
    <AppLayout>
      {/* Page header */}
      <div className="border-b border-mist pb-6 mb-8 flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="px-2 py-0.5 rounded bg-surface-container border border-mist text-ash text-[11px] font-code-compact">DS-ID: 2025-05-89X</span>
            <span className="text-ash text-body-caption">·</span>
            <span className="text-ash text-body-caption">Compartment Alpha-Seven</span>
          </div>
          <h1 className="font-headline-xl text-headline-xl text-graphite tracking-tight">Overview</h1>
          <p className="font-body-reading text-ash text-[15px] mt-1">Operational Threat Intelligence &amp; Disruption Summary</p>
        </div>
        <div className="text-code-default font-code-default text-charcoal text-[13px] bg-paper px-3 py-1.5 rounded-lg border border-mist shadow-sm">
          {clock || "Cycle: —"}
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {[
          { label: "Actors Tracked", value: actorCount, icon: "groups", badge: "+3 this month", badgeCls: "text-status-live" },
          { label: "Active Groups", value: activeCount, icon: "deployed_code", badge: "High syndicate posture", badgeCls: "text-charcoal" },
          { label: "Events (24h)", value: (events24h ?? 0).toLocaleString(), icon: "dynamic_feed", badge: "↑ live ingests", badgeCls: "text-cerulean" },
          { label: "Unread Alerts", value: safeAlerts.length, icon: "crisis_alert", badge: `${safeAlerts.filter(a => a?.severity === "critical").length} critical`, badgeCls: "text-severity-critical", valueCls: "text-severity-critical" },
        ].map((card) => (
          <div key={card.label} className="bg-paper p-space-md rounded-xl border border-mist shadow-editorial flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2">
              <span className="text-label-ui font-label-ui text-ash">{card.label}</span>
              <span className="material-symbols-outlined text-ash text-[18px]">{card.icon}</span>
            </div>
            <div className="flex items-baseline justify-between mt-1">
              <span className={`font-headline-xl text-headline-xl leading-none ${card.valueCls ?? "text-graphite"}`}>{card.value}</span>
              <span className={`inline-flex items-center text-[11px] font-label-uppercase px-2 py-0.5 rounded-full bg-linen border border-mist font-medium ${card.badgeCls}`}>
                {card.badge}
              </span>
            </div>
            <div className="mt-3 pt-2.5 border-t border-mist/60 text-[12px] font-body-caption text-ash">
              {card.label === "Actors Tracked" ? "5 advanced persistent campaigns" :
               card.label === "Active Groups" ? "Cluster delta: 0 net closures" :
               card.label === "Events (24h)" ? "Normalized across sources" :
               "Immediate triage mandated"}
            </div>
          </div>
        ))}
      </div>

      {/* 2-column grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left col */}
        <div className="lg:col-span-8 space-y-8">
          {/* Source health */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-headline-lg text-headline-lg text-graphite">Source Status</h3>
                <p className="text-body-caption text-ash">Health telemetry across primary crawler nodes and continuous listeners</p>
              </div>
              <button
                onClick={() => pipeline.health().then((s) => { if (Array.isArray(s)) setSources(s); }).catch(() => {})}
                className="inline-flex items-center gap-1 text-label-ui font-label-ui text-charcoal hover:text-cerulean transition-colors"
              >
                <span className="material-symbols-outlined text-[16px]">refresh</span>
                <span>Poll All</span>
              </button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {!Array.isArray(sources) || sources.length === 0 ? (
                Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="bg-paper border border-mist rounded-xl p-4 animate-pulse">
                    <div className="h-3 bg-linen rounded mb-2 w-3/4" />
                    <div className="h-2 bg-linen rounded w-1/2" />
                  </div>
                ))
              ) : sources.map((src) => (
                <div key={src.name} className="bg-paper border border-mist rounded-xl p-4 shadow-diagram">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-body-emphasis text-body-default text-ink-black">{src.name}</span>
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${statusDot[src.status] ?? "bg-fog"}`} />
                      <span className="text-[11px] font-code-compact text-ash capitalize">{src.status}</span>
                    </div>
                  </div>
                  <div className="text-[12px] font-body-caption text-ash">
                    {src.last_success ? `Last: ${new Date(src.last_success).toLocaleTimeString()}` : "Not run"}
                  </div>
                  <div className="text-[12px] font-code-compact text-charcoal mt-1">
                    {src.events_24h.toLocaleString()} events / 24h
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent alerts */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-headline-lg text-headline-lg text-graphite">Recent Alerts</h3>
              <Link href="/alerts" className="text-label-ui font-label-ui text-cerulean hover:opacity-80 transition-opacity flex items-center gap-1">
                View all <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
              </Link>
            </div>
            {safeAlerts.length === 0 ? (
              <div className="bg-paper border border-mist rounded-xl p-6 text-center text-ash text-body-caption">
                No active threat alerts matching current filters.
              </div>
            ) : safeAlerts.map((a) => (
              <div key={a.id} className={`bg-paper border border-mist rounded-xl p-4 shadow-editorial border-l-4 ${severityBorder[a.severity] ?? "border-l-fog"}`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[11px] font-label-uppercase tracking-widest font-semibold text-${a.severity === "critical" ? "severity-critical" : a.severity === "high" ? "severity-high" : "severity-medium"}`}>
                        {a.severity.toUpperCase()}
                      </span>
                      {a.actor_handle && (
                        <Link href={`/actors/${a.actor_id}`} className="text-[11px] font-label-ui text-cerulean hover:opacity-80">
                          {a.actor_handle}
                        </Link>
                      )}
                    </div>
                    <p className="font-body-default text-body-default text-graphite line-clamp-1">{a.title}</p>
                    <p className="font-body-caption text-body-caption text-ash mt-0.5 line-clamp-1">{a.body}</p>
                  </div>
                  <Link href="/alerts" className="text-cerulean hover:opacity-80 shrink-0">
                    <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right col */}
        <div className="lg:col-span-4 space-y-4">
          {/* Live feed */}
          <div className="bg-paper border border-mist rounded-xl shadow-editorial h-[420px] flex flex-col overflow-hidden">
            <div className="p-4 border-b border-mist flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-status-live animate-pulse" />
                <span className="font-body-emphasis text-body-default text-graphite">Live Feed</span>
              </div>
              <span className="text-[11px] font-code-compact text-ash">ws://feed</span>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-2 custom-scroll">
              {feed.length === 0 ? (
                <p className="text-ash font-body-caption text-body-caption text-center mt-8">Waiting for events…</p>
              ) : feed.map((ev) => (
                <div key={ev.id} className="border-b border-mist/50 pb-2 last:border-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="font-code-compact text-code-compact text-ash">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="bg-surface-container border border-mist px-1.5 py-0.5 rounded text-[10px] font-label-ui text-charcoal">
                      {ev.source}
                    </span>
                    {ev.severity && ev.severity !== "info" && (
                      <span className={`text-[10px] font-label-uppercase px-1.5 py-0.5 rounded ${
                        ev.severity === "critical" ? "bg-severity-critical/10 text-severity-critical" :
                        ev.severity === "warning" ? "bg-severity-medium/10 text-severity-medium" :
                        "bg-linen text-ash"
                      }`}>{ev.severity}</span>
                    )}
                  </div>
                  {ev.title ? (
                    <p className="text-[12px] font-body-reading text-graphite">{ev.title}</p>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {ev.entity_kinds?.map((k) => (
                        <span key={k} className="text-[10px] font-label-uppercase bg-linen border border-mist text-ash px-1.5 py-0.5 rounded">{k}</span>
                      ))}
                    </div>
                  )}
                  {ev.entities_found != null && ev.entities_found > 0 && (
                    <span className="text-[10px] font-code-compact text-cerulean mt-0.5 inline-block">
                      {ev.entities_found.toLocaleString()} items
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Quick actions */}
          <div className="bg-paper border border-mist rounded-xl p-4 shadow-editorial">
            <h4 className="font-body-emphasis text-body-default text-graphite mb-3">Quick Actions</h4>
            <div className="space-y-2">
              {[
                { label: "Run Graph Analytics", icon: "hub", href: "/pipeline" },
                { label: "Browse All Actors", icon: "person_alert", href: "/actors" },
                { label: "Search Intelligence", icon: "search", href: "/search" },
                { label: "Triage Alerts", icon: "notifications_active", href: "/alerts" },
              ].map((action) => (
                <Link key={action.label} href={action.href}
                  className="flex items-center gap-2.5 px-3 py-2 rounded-lg hover:bg-linen text-charcoal hover:text-ink-black transition-colors font-label-ui text-label-ui">
                  <span className="material-symbols-outlined text-[18px]">{action.icon}</span>
                  <span>{action.label}</span>
                  <span className="material-symbols-outlined text-[16px] ml-auto text-ash">arrow_forward</span>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
