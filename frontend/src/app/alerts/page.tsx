"use client";
import { useEffect, useState } from "react";
import AppLayout from "@/components/AppLayout";
import { alertsApi, type Alert } from "@/lib/api";
import { useWebSocket } from "@/lib/useWebSocket";
import Link from "next/link";

type FilterStatus = "all" | "unread" | "acknowledged" | "dismissed";
type FilterSeverity = "all" | "critical" | "high" | "medium" | "low";

const severityBorder: Record<string, string> = {
  critical: "border-l-severity-critical",
  high: "border-l-severity-high",
  medium: "border-l-severity-medium",
  low: "border-l-severity-low",
};
const severityText: Record<string, string> = {
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [statusFilter, setStatusFilter] = useState<FilterStatus>("unread");
  const [severityFilter, setSeverityFilter] = useState<FilterSeverity>("all");
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  const fetchAlerts = () => {
    setLoading(true);
    const params: Record<string, string> = {};
    if (statusFilter !== "all") params.status = statusFilter;
    if (severityFilter !== "all") params.severity = severityFilter;
    alertsApi.list(params)
      .then((r) => {
        const items = Array.isArray(r) ? r : Array.isArray(r?.items) ? r.items : [];
        setAlerts(items.filter(Boolean));
        setTotal(typeof r?.total === "number" ? r.total : items.length);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchAlerts(); }, [statusFilter, severityFilter]);

  useWebSocket((msg) => {
    if (msg.channel === "alerts" && msg.data) {
      const newAlert = msg.data as Alert;
      if (newAlert && newAlert.id) {
        setAlerts((prev) => [newAlert, ...prev]);
        setTotal((t) => t + 1);
      }
    }
  }, ["alerts"]);

  const handleAction = (id: string, action: "acknowledged" | "dismissed") => {
    alertsApi.patch(id, action).then(() => {
      setAlerts((prev) => prev.filter(Boolean).map((a) => a.id === id ? { ...a, status: action } : a));
      if (statusFilter !== "all") setAlerts((prev) => prev.filter((a) => a && (a.id !== id || a.status === statusFilter)));
    }).catch(() => {});
  };

  return (
    <AppLayout>
      <div className="flex gap-6 h-[calc(100vh-160px)]">
        {/* Left: Alert feed */}
        <div className="flex-1 min-w-0 flex flex-col">
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-6 border-b border-mist pb-6">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <h1 className="font-headline-xl text-headline-xl text-ink-black tracking-tight font-normal">Alerts</h1>
                <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-error-container text-on-error-container font-code-compact text-code-compact border border-error/20">
                  {total} Unresolved
                </span>
              </div>
              <p className="text-ash font-body-caption text-body-caption">
                Real-time heuristic &amp; correlation trigger queue · Requiring analytical triage
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-mist bg-paper hover:bg-linen text-charcoal font-label-ui text-label-ui transition-colors">
                <span className="material-symbols-outlined text-sm">done_all</span>
                Batch Acknowledge All
              </button>
            </div>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
            <div className="flex items-center gap-1 bg-surface-container-low p-1 rounded-lg border border-mist">
              {(["all", "unread", "acknowledged", "dismissed"] as FilterStatus[]).map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-2.5 py-1 font-label-ui text-label-ui rounded capitalize transition-colors ${
                    statusFilter === s
                      ? "bg-paper text-ink-black font-semibold shadow-sm"
                      : "text-ash hover:text-charcoal"
                  }`}
                >
                  {s} {s === "unread" ? `(${alerts.filter((a) => a?.status === "unread").length})` : ""}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-1">
              {(["all", "critical", "high", "medium", "low"] as FilterSeverity[]).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={`px-2.5 py-1 font-label-ui text-label-ui rounded capitalize transition-colors text-[12px] ${
                    severityFilter === s
                      ? "bg-primary-container text-paper"
                      : "border border-mist text-ash hover:bg-linen"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Alert list */}
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="bg-paper border border-mist rounded-xl p-4 animate-pulse h-24" />
              ))
            ) : alerts.length === 0 ? (
              <div className="text-center py-20">
                <span className="material-symbols-outlined text-[48px] text-fog mb-3">notifications_off</span>
                <p className="font-headline-xl text-headline-xl text-graphite">No Alerts</p>
                <p className="font-body-caption text-ash mt-2">Queue is clear for current filters.</p>
              </div>
            ) : alerts.filter(Boolean).map((alert) => (
              <div
                key={alert.id}
                onClick={() => setSelected(alert)}
                className={`bg-paper border border-mist rounded-xl p-4 shadow-editorial border-l-4 ${severityBorder[alert.severity] ?? "border-l-fog"} cursor-pointer hover:shadow-diagram transition-shadow ${selected?.id === alert.id ? "ring-1 ring-cerulean" : ""}`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`text-[10px] font-label-uppercase tracking-widest font-semibold ${severityText[alert.severity]}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      {alert.actor_handle && (
                        <Link
                          href={`/actors/${alert.actor_id}`}
                          className="text-[11px] font-label-ui text-cerulean hover:opacity-80"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {alert.actor_handle}
                        </Link>
                      )}
                      <span className="font-code-compact text-code-compact text-ash ml-auto text-[11px]">
                        {alert.created_at?.slice(0, 16)?.replace("T", " ")}
                      </span>
                    </div>
                    <p className="font-body-default text-body-default text-graphite line-clamp-1">{alert.title}</p>
                    <p className="font-body-caption text-body-caption text-ash mt-0.5 line-clamp-1">{alert.body}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 mt-3 pt-3 border-t border-mist/50">
                  <button
                    onClick={(e) => { e.stopPropagation(); handleAction(alert.id, "acknowledged"); }}
                    className="text-[12px] font-label-ui text-charcoal hover:text-cerulean transition-colors flex items-center gap-1"
                  >
                    <span className="material-symbols-outlined text-[14px]">check_circle</span> Acknowledge
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleAction(alert.id, "dismissed"); }}
                    className="text-[12px] font-label-ui text-ash hover:text-charcoal transition-colors flex items-center gap-1"
                  >
                    <span className="material-symbols-outlined text-[14px]">cancel</span> Dismiss
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Detail panel */}
        <div className={`w-[380px] shrink-0 ${selected ? "block" : "hidden lg:block"}`}>
          {selected ? (
            <div className="bg-paper border border-mist rounded-xl p-6 shadow-editorial sticky top-24 h-full overflow-y-auto">
              <div className="flex items-start justify-between mb-4">
                <span className={`text-[10px] font-label-uppercase font-semibold ${severityText[selected.severity]}`}>
                  {selected.severity.toUpperCase()} · {selected.alert_type}
                </span>
                <button onClick={() => setSelected(null)} className="text-ash hover:text-charcoal transition-colors">
                  <span className="material-symbols-outlined text-[20px]">close</span>
                </button>
              </div>
              <h2 className="font-headline-lg text-headline-lg text-graphite mb-4">{selected.title}</h2>
              <div className="h-[1px] bg-mist mb-4" />
              <p className="font-body-reading text-body-reading text-charcoal mb-6">{selected.body}</p>
              {selected.actor_handle && (
                <div className="mb-4 p-3 bg-surface-container-low border border-mist rounded-lg">
                  <span className="text-[10px] font-label-uppercase text-ash">RELATED ACTOR</span>
                  <Link href={`/actors/${selected.actor_id}`} className="block font-body-emphasis text-body-default text-cerulean hover:opacity-80 mt-1">
                    {selected.actor_handle}
                  </Link>
                </div>
              )}
              <div className="space-y-2">
                <button onClick={() => handleAction(selected.id, "acknowledged")}
                  className="w-full border border-cerulean text-cerulean hover:opacity-80 font-label-ui text-label-ui py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition-opacity">
                  <span className="material-symbols-outlined text-[16px]">check_circle</span> Acknowledge
                </button>
                <button onClick={() => handleAction(selected.id, "dismissed")}
                  className="w-full border border-twilight text-twilight hover:bg-linen font-label-ui text-label-ui py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition-colors">
                  <span className="material-symbols-outlined text-[16px]">cancel</span> Dismiss
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-linen border border-mist rounded-xl p-8 text-center sticky top-24">
              <span className="material-symbols-outlined text-[40px] text-fog mb-3">touch_app</span>
              <p className="font-body-reading text-ash">Select an alert to view full details</p>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
