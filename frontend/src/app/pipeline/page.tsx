"use client";
import { useEffect, useState } from "react";
import AppLayout from "@/components/AppLayout";
import { pipeline, type SourceHealth, type TaskStatus, type PipelineMetrics } from "@/lib/api";

type PipelineTab = "sources" | "triggers" | "tasks" | "metrics";

export default function PipelinePage() {
  const [tab, setTab] = useState<PipelineTab>("sources");
  const [sources, setSources] = useState<SourceHealth[]>([]);
  const [metrics, setMetrics] = useState<PipelineMetrics | null>(null);
  const [tasks, setTasks] = useState<TaskStatus[]>([]);
  const [loading, setLoading] = useState(true);

  // Trigger form states
  const [btcAddresses, setBtcAddresses] = useState("");
  const [onionUrls, setOnionUrls] = useState("");
  const [crawlQueries, setCrawlQueries] = useState("");
  const [taskFeedback, setTaskFeedback] = useState<string | null>(null);

  useEffect(() => {
    pipeline.health().then((s) => {
      if (Array.isArray(s)) setSources(s);
    }).catch(() => {}).finally(() => setLoading(false));
    pipeline.metrics().then(setMetrics).catch(() => {});
  }, []);

  const statusDot: Record<string, string> = {
    online: "bg-status-live",
    degraded: "bg-status-warn",
    offline: "bg-status-error",
  };

  const triggerAction = async (fn: () => Promise<any>, label: string) => {
    setTaskFeedback(`Starting ${label}…`);
    try {
      const r = await fn();
      const tid = r?.task_id || (r?.count ? `${r.count} tasks` : "active");
      const shortId = typeof tid === "string" ? tid.slice(0, 8) : String(tid);
      setTaskFeedback(`✓ ${label} started · task: ${shortId}…`);
    } catch (err) {
      setTaskFeedback(`✗ ${label} failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }
    setTimeout(() => setTaskFeedback(null), 5000);
  };

  const tabs: { key: PipelineTab; label: string; icon: string }[] = [
    { key: "sources", label: "Sources", icon: "sensors" },
    { key: "triggers", label: "Triggers", icon: "play_circle" },
    { key: "tasks", label: "Tasks", icon: "task_alt" },
    { key: "metrics", label: "Metrics", icon: "analytics" },
  ];

  const taskStatusColor: Record<string, string> = {
    PENDING: "bg-fog",
    RUNNING: "bg-status-warn",
    SUCCESS: "bg-status-live",
    FAILURE: "bg-status-error",
  };

  return (
    <AppLayout>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-6 border-b border-mist pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-code-compact text-code-compact text-ash tracking-widest uppercase">COLLECTION CONTROL CENTER</span>
            <span className="text-mist">/</span>
            <span className="font-code-compact text-code-compact text-status-live">
              {sources.filter(s => s.status === "online").length}/{sources.length} ONLINE
            </span>
          </div>
          <h1 className="font-headline-xl text-headline-xl text-graphite tracking-tight">Pipeline</h1>
          <p className="font-body-caption text-ash">Live data collection control, on-demand triggers, and telemetry</p>
        </div>
      </div>

      {/* Task feedback toast */}
      {taskFeedback && (
        <div className="mb-4 p-3 bg-paper border border-mist rounded-xl shadow-editorial font-code-compact text-code-compact text-charcoal flex items-center gap-2">
          <span className="material-symbols-outlined text-[16px] text-cerulean">info</span>
          {taskFeedback}
        </div>
      )}

      {/* Tab nav */}
      <div className="flex items-center gap-0 border-b border-mist mb-6">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-1.5 px-4 py-3 font-label-ui text-label-ui transition-colors ${
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

      {/* Sources tab */}
      {tab === "sources" && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="font-body-caption text-ash">Health telemetry across all collection adapters</p>
            <button
              onClick={() => pipeline.health().then(setSources).catch(() => {})}
              className="inline-flex items-center gap-1.5 border border-twilight text-twilight hover:bg-linen font-label-ui text-label-ui px-3 py-1.5 rounded-lg transition-colors"
            >
              <span className="material-symbols-outlined text-[16px]">refresh</span> Poll All
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
            {loading || !Array.isArray(sources) ? (
              Array.from({ length: 9 }).map((_, i) => (
                <div key={i} className="bg-paper border border-mist rounded-xl p-4 animate-pulse h-28" />
              ))
            ) : sources.map((src) => (
              <div key={src.name} className="bg-paper border border-mist rounded-xl p-4 shadow-editorial">
                <div className="flex items-center justify-between mb-3">
                  <span className="font-body-emphasis text-body-default text-ink-black">{src.name}</span>
                  <div className="flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full ${statusDot[src.status] ?? "bg-fog"}`} />
                    <span className="text-[11px] font-code-compact text-ash capitalize">{src.status}</span>
                  </div>
                </div>
                <div className="space-y-1 mb-3">
                  <div className="flex justify-between text-[12px]">
                    <span className="font-body-caption text-ash">Last success</span>
                    <span className="font-code-compact text-charcoal">
                      {src.last_success ? new Date(src.last_success).toLocaleTimeString() : "—"}
                    </span>
                  </div>
                  <div className="flex justify-between text-[12px]">
                    <span className="font-body-caption text-ash">Events (24h)</span>
                    <span className="font-code-compact text-charcoal">{src.events_24h.toLocaleString()}</span>
                  </div>
                  {src.next_run && (
                    <div className="flex justify-between text-[12px]">
                      <span className="font-body-caption text-ash">Next run</span>
                      <span className="font-code-compact text-ash">{new Date(src.next_run).toLocaleTimeString()}</span>
                    </div>
                  )}
                </div>
                <button
                  onClick={() => triggerAction(() => pipeline.triggerSource(src.name), src.name)}
                  className="w-full border border-cerulean text-cerulean hover:opacity-80 font-label-ui text-label-ui py-1.5 px-3 rounded-lg text-[13px] flex items-center justify-center gap-1 transition-opacity"
                >
                  <span className="material-symbols-outlined text-[15px]">play_arrow</span> Trigger Now →
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Triggers tab */}
      {tab === "triggers" && (
        <div className="max-w-2xl space-y-4">
          {/* Trigger All */}
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-1">Trigger All Sources</h3>
            <p className="font-body-caption text-ash mb-4">Immediately run all 22 collection adapters in parallel.</p>
            <button
              onClick={() => triggerAction(() => pipeline.triggerAll(), "all sources")}
              className="bg-primary-container hover:bg-twilight text-paper font-label-ui text-label-ui px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
            >
              <span className="material-symbols-outlined text-[16px]">play_circle</span> Run All Sources
            </button>
          </div>

          {/* Blockchain Lookup */}
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-1">Blockchain Lookup</h3>
            <p className="font-body-caption text-ash mb-3">Resolve BTC/ETH wallet addresses via Mempool + Etherscan.</p>
            <textarea
              value={btcAddresses}
              onChange={(e) => setBtcAddresses(e.target.value)}
              rows={4}
              className="ledger-input w-full py-2 font-code-compact text-code-compact text-charcoal resize-none mb-3"
              placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf…&#10;0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            />
            <button
              onClick={() => {
                const addresses = btcAddresses.split("\n").map(s => s.trim()).filter(Boolean);
                if (addresses.length === 0) {
                  setTaskFeedback("✗ Blockchain lookup: enter at least one BTC or ETH address");
                  setTimeout(() => setTaskFeedback(null), 4000);
                  return;
                }
                triggerAction(() => pipeline.blockchainLookup(addresses), "blockchain lookup");
              }}
              className="border border-cerulean text-cerulean hover:opacity-80 font-label-ui text-label-ui px-4 py-2 rounded-lg flex items-center gap-2 transition-opacity"
            >
              <span className="material-symbols-outlined text-[16px]">account_balance_wallet</span> Lookup →
            </button>
          </div>

          {/* Onion Probe */}
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-1">Onion Probe</h3>
            <p className="font-body-caption text-ash mb-3">Test uptime, clock-skew and favicon of .onion addresses (max 20).</p>
            <textarea
              value={onionUrls}
              onChange={(e) => setOnionUrls(e.target.value)}
              rows={4}
              className="ledger-input w-full py-2 font-code-compact text-code-compact text-charcoal resize-none mb-3"
              placeholder="facebookwkhpilnemxj.onion&#10;dreadytofatroptsdj6io7l3xptbet6on.onion"
            />
            <button
              onClick={() => {
                const urls = onionUrls.split("\n").map(s => s.trim()).filter(Boolean);
                if (urls.length === 0) {
                  setTaskFeedback("✗ Onion probe: enter at least one .onion URL");
                  setTimeout(() => setTaskFeedback(null), 4000);
                  return;
                }
                triggerAction(() => pipeline.probeLookup(urls), "onion probe");
              }}
              className="border border-cerulean text-cerulean hover:opacity-80 font-label-ui text-label-ui px-4 py-2 rounded-lg flex items-center gap-2 transition-opacity"
            >
              <span className="material-symbols-outlined text-[16px]">travel_explore</span> Probe →
            </button>
          </div>

          {/* Crawl */}
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-1">Onion Crawl</h3>
            <p className="font-body-caption text-ash mb-3">Crawl via Ahmia + BFS with keyword queries.</p>
            <input
              type="text"
              value={crawlQueries}
              onChange={(e) => setCrawlQueries(e.target.value)}
              className="ledger-input w-full py-2 font-body-default text-body-default text-charcoal mb-3"
              placeholder="ransomware, darknet market, PGP key server"
            />
            <button
              onClick={() => {
                const queries = crawlQueries.split(",").map(s => s.trim()).filter(Boolean);
                if (queries.length === 0) {
                  setTaskFeedback("✗ Onion crawl: enter at least one keyword");
                  setTimeout(() => setTaskFeedback(null), 4000);
                  return;
                }
                triggerAction(() => pipeline.crawl(queries), "onion crawl");
              }}
              className="border border-cerulean text-cerulean hover:opacity-80 font-label-ui text-label-ui px-4 py-2 rounded-lg flex items-center gap-2 transition-opacity"
            >
              <span className="material-symbols-outlined text-[16px]">network_node</span> Crawl →
            </button>
          </div>

          {/* Graph Analytics */}
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-1">Graph Analytics</h3>
            <p className="font-body-caption text-ash mb-4">Run wallet clustering (common-input-ownership), clock-skew correlation, favicon fingerprint edges, and actor merge candidates.</p>
            <button
              onClick={() => triggerAction(() => pipeline.runAnalytics(), "graph analytics")}
              className="bg-primary-container hover:bg-twilight text-paper font-label-ui text-label-ui px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
            >
              <span className="material-symbols-outlined text-[16px]">hub</span> Run Analytics
            </button>
          </div>
        </div>
      )}

      {/* Tasks tab */}
      {tab === "tasks" && (
        <div className="bg-paper border border-mist rounded-xl overflow-hidden shadow-editorial">
          <div className="flex items-center justify-between p-4 border-b border-mist">
            <span className="font-body-emphasis text-body-default text-graphite">Task Queue</span>
            <button className="text-label-ui font-label-ui text-ash hover:text-charcoal flex items-center gap-1 transition-colors">
              <span className="material-symbols-outlined text-[16px]">refresh</span> Refresh
            </button>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-mist">
                {["Task Name", "Status", "Started", "Duration", "Result"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-[11px] font-label-uppercase text-ash tracking-[0.06em]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tasks.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-16 text-center">
                    <span className="material-symbols-outlined text-[40px] text-fog mb-2">task_alt</span>
                    <p className="font-body-reading text-ash">No active tasks. Trigger collection above.</p>
                  </td>
                </tr>
              ) : tasks.map((task) => (
                <tr key={task.task_id} className="border-b border-mist hover:bg-linen transition-colors">
                  <td className="px-4 py-3 font-body-default text-body-default text-charcoal">{task.name}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${taskStatusColor[task.status] ?? "bg-fog"} ${task.status === "RUNNING" ? "animate-pulse" : ""}`} />
                      <span className="font-label-ui text-label-ui text-charcoal">{task.status}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-code-compact text-code-compact text-ash">{task.started_at?.slice(0, 16)?.replace("T", " ") ?? "—"}</td>
                  <td className="px-4 py-3 font-code-compact text-code-compact text-ash">—</td>
                  <td className="px-4 py-3 font-body-caption text-body-caption text-ash">{task.status === "SUCCESS" ? "Completed" : task.status === "FAILURE" ? "Failed" : "Running…"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Metrics tab */}
      {tab === "metrics" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Events 7d bar chart */}
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-4">Events (7 days)</h3>
            {metrics ? (
              <div className="flex items-end gap-2 h-32">
                {metrics.events_7d.map((v, i) => {
                  const max = Math.max(...metrics.events_7d, 1);
                  return (
                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                      <span className="text-[10px] font-code-compact text-ash">{v.toLocaleString()}</span>
                      <div className="w-full bg-linen rounded-sm" style={{ height: `${Math.round((v / max) * 100)}px`, backgroundColor: "#282834" }} />
                      <span className="text-[10px] font-code-compact text-ash">D-{6 - i}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="h-32 flex items-center justify-center text-ash font-body-caption">Loading…</div>
            )}
          </div>

          {/* Entity breakdown */}
          <div className="bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-4">Entity Types</h3>
            {metrics?.entity_breakdown ? (
              <div className="space-y-2">
                {Object.entries(metrics.entity_breakdown).map(([kind, count]) => {
                  const total = Object.values(metrics.entity_breakdown).reduce((a, b) => a + b, 0);
                  const pct = Math.round((count / total) * 100);
                  return (
                    <div key={kind}>
                      <div className="flex justify-between mb-1">
                        <span className="font-label-ui text-label-ui text-charcoal capitalize">{kind}</span>
                        <span className="font-code-compact text-code-compact text-ash">{count.toLocaleString()} ({pct}%)</span>
                      </div>
                      <div className="h-1.5 bg-linen rounded-full overflow-hidden">
                        <div className="h-full bg-twilight rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center text-ash font-body-caption py-8">Loading…</div>
            )}
          </div>

          {/* Source contribution */}
          <div className="lg:col-span-2 bg-paper border border-mist rounded-xl p-5 shadow-editorial">
            <h3 className="font-headline-sub text-headline-sub text-graphite mb-4">Source Contribution</h3>
            {metrics?.source_breakdown ? (
              <div className="space-y-2">
                {Object.entries(metrics.source_breakdown)
                  .sort(([, a], [, b]) => b - a)
                  .map(([src, count]) => {
                    const max = Math.max(...Object.values(metrics.source_breakdown), 1);
                    return (
                      <div key={src} className="flex items-center gap-3">
                        <span className="font-label-ui text-label-ui text-charcoal w-40 truncate shrink-0">{src}</span>
                        <div className="flex-1 h-2 bg-linen rounded-full overflow-hidden">
                          <div className="h-full bg-twilight rounded-full" style={{ width: `${Math.round((count / max) * 100)}%` }} />
                        </div>
                        <span className="font-code-compact text-code-compact text-ash w-20 text-right">{count.toLocaleString()}</span>
                      </div>
                    );
                  })}
              </div>
            ) : (
              <div className="text-center text-ash font-body-caption py-8">Loading…</div>
            )}
          </div>
        </div>
      )}
    </AppLayout>
  );
}
