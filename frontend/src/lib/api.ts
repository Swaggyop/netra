/**
 * NETRA API client
 * All requests go to /api/v1/* proxied to backend at localhost:8000
 */

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const WS_BASE = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000";

export const API_BASE = `${BASE}/api/v1`;
export const HEALTH_BASE = `${BASE}/health`;
export const WS_FEED = `${WS_BASE}/ws/feed`;

// ── Auth token storage ────────────────────────────────────────────────────────
export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("netra_token");
}
export function setToken(token: string) {
  localStorage.setItem("netra_token", token);
}
export function clearToken() {
  localStorage.removeItem("netra_token");
}

// ── Core fetch wrapper ────────────────────────────────────────────────────────
async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...((options.headers as Record<string, string>) ?? {}),
    },
    ...options,
  });
  if (res.status === 401) {
    // Token expired or invalid — clear and redirect to login
    clearToken();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
    throw new Error("Session expired. Please log in again.");
  }
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail?.detail ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
export interface LoginResponse {
  access_token: string;
  token_type: string;
}
export const auth = {
  login: (username: string, password: string) =>
    apiFetch<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
};

// ── Actors ────────────────────────────────────────────────────────────────────
export interface Actor {
  id: string;
  handle: string;
  aliases: string[];
  category: string;
  status: "active" | "dormant" | "defunct";
  confidence_score: number;
  confidence_band: "A" | "B" | "C" | "D" | "E";
  first_seen: string;
  last_seen: string;
  entity_count: number;
  link_count: number;
  notes: string | null;
  entities?: any[];
  links?: any[];
}
export interface ActorsResponse {
  items: Actor[];
  total: number;
  page: number;
  page_size: number;
}
export const actors = {
  list: async (params?: Record<string, string | number>): Promise<ActorsResponse> => {
    const qs = params ? "?" + new URLSearchParams(params as Record<string, string>).toString() : "";
    try {
      const res = await apiFetch<any>(`/actors${qs}`);
      const rawList = Array.isArray(res) ? res : Array.isArray(res?.items) ? res.items : [];
      const total = typeof res?.total === "number" ? res.total : rawList.length;

      const items: Actor[] = rawList.map((a: any) => ({
        id: a.id || a.actor_id || crypto.randomUUID(),
        handle: a.handle || a.label || "Unknown Actor",
        aliases: a.aliases || [],
        category: a.category || "threat_group",
        status: a.status || "active",
        confidence_score: a.confidence_score ?? 85,
        confidence_band: a.confidence_band || (a.confidence_score >= 80 ? "A" : a.confidence_score >= 60 ? "B" : "C"),
        first_seen: a.first_seen || new Date().toISOString(),
        last_seen: a.last_seen || new Date().toISOString(),
        entity_count: a.entity_count ?? (a.entities?.length ?? 0),
        link_count: a.link_count ?? (a.links?.length ?? 0),
        notes: a.notes ?? null,
      }));

      return {
        items,
        total,
        page: typeof params?.page === "number" ? params.page : 1,
        page_size: typeof params?.page_size === "number" ? params.page_size : 20,
      };
    } catch {
      return { items: [], total: 0, page: 1, page_size: 20 };
    }
  },
  get: async (id: string): Promise<Actor> => {
    const a = await apiFetch<any>(`/actors/${id}`);
    return {
      id: a.id || a.actor_id || id,
      handle: a.handle || a.label || "Unknown Actor",
      aliases: a.aliases || [],
      category: a.category || "threat_group",
      status: a.status || "active",
      confidence_score: a.confidence_score ?? 85,
      confidence_band: a.confidence_band || "A",
      first_seen: a.first_seen || new Date().toISOString(),
      last_seen: a.last_seen || new Date().toISOString(),
      entity_count: a.entities?.length ?? 0,
      link_count: a.links?.length ?? 0,
      notes: a.notes ?? null,
      entities: a.entities ?? [],
      links: a.links ?? [],
    };
  },
  patch: (id: string, body: Partial<Actor>) =>
    apiFetch<Actor>(`/actors/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  graph: (id: string, depth = 2) =>
    apiFetch<GraphData>(`/actors/${id}/graph?depth=${depth}`),
  overviewGraph: (limit = 300) =>
    apiFetch<GraphData>(`/actors/graph/overview?limit=${limit}`),
  links: (id: string) => apiFetch<RebrandLink[]>(`/actors/${id}/links`),
};

// ── Graph ─────────────────────────────────────────────────────────────────────
export interface GraphNode {
  id: string;
  label: string;
  kind: "Actor" | "Wallet" | "PGP" | "PGPKey" | "Onion" | "Email" | "Handle" | "Domain" | "IP" | string;
  properties?: Record<string, unknown>;
}
export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  properties?: Record<string, unknown>;
}
export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ── Entities ──────────────────────────────────────────────────────────────────
export interface Entity {
  id: string;
  kind: string;
  value: string;
  first_seen: string;
  confidence: number;
  source: string;
}

// ── Rebrand links ─────────────────────────────────────────────────────────────
export interface RebrandLink {
  id: string;
  old_actor: Actor;
  new_actor: Actor;
  score: number;
  signals: string[];
  detected_at: string;
}

// ── Alerts ────────────────────────────────────────────────────────────────────
export interface Alert {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  alert_type: string;
  title: string;
  body: string;
  actor_id: string | null;
  actor_handle: string | null;
  status: "unread" | "acknowledged" | "dismissed";
  created_at: string;
}
export interface AlertsResponse {
  items: Alert[];
  total: number;
}
export const alertsApi = {
  list: async (params?: Record<string, string>): Promise<AlertsResponse> => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    try {
      const res = await apiFetch<any>(`/alerts${qs}`);
      const rawList = Array.isArray(res) ? res : Array.isArray(res?.items) ? res.items : [];
      const total = typeof res?.total === "number" ? res.total : rawList.length;

      const items: Alert[] = rawList.map((a: any) => ({
        id: a.id || a.alert_id || crypto.randomUUID(),
        severity: a.severity || (a.score && a.score > 0.8 ? "critical" : a.score && a.score > 0.6 ? "high" : a.score && a.score > 0.4 ? "medium" : "low"),
        alert_type: a.alert_type || "threat_detection",
        title: a.title || a.subject?.title || a.subject?.name || `Alert ${a.alert_type || ""}`.trim(),
        body: a.body || a.subject?.description || (typeof a.subject === "object" ? JSON.stringify(a.subject) : ""),
        actor_id: a.actor_id || a.subject?.actor_id || null,
        actor_handle: a.actor_handle || a.subject?.actor_handle || null,
        status: a.status || "unread",
        created_at: a.created_at || new Date().toISOString(),
      }));

      return { items, total };
    } catch {
      return { items: [], total: 0 };
    }
  },
  patch: (id: string, status: string) =>
    apiFetch<Alert>(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
};

// ── Search ────────────────────────────────────────────────────────────────────
export interface SearchResult {
  type: "actor" | "entity" | "event" | "infra";
  id: string;
  primary: string;
  snippet: string;
  source: string;
  date: string;
}
export const search = {
  query: (q: string, type?: string) =>
    apiFetch<SearchResult[]>(`/search?q=${encodeURIComponent(q)}${type ? `&type=${type}` : ""}`),
};

// ── Timeline ──────────────────────────────────────────────────────────────────
export interface TimelineEvent {
  id: string;
  source: string;
  entity_kinds: string[];
  snippet: string;
  occurred_at: string;
}
export const timeline = {
  get: (actor_id: string) => apiFetch<TimelineEvent[]>(`/timeline?actor_id=${actor_id}`),
};

// ── Infrastructure ────────────────────────────────────────────────────────────
export interface InfraRecord {
  id: string;
  onion_url: string;
  uptime_pct: number;
  last_probed: string;
  clock_skew_ms: number | null;
  favicon_hash: string | null;
  status: "up" | "down" | "unknown";
}
export const infra = {
  get: (actor_id: string) => apiFetch<InfraRecord[]>(`/infra?actor_id=${actor_id}`),
};

// ── Provenance ────────────────────────────────────────────────────────────────
export interface ProvenanceRecord {
  event_id: string;
  source: string;
  admiralty_grade: string;
  collected_at: string;
  content_hash: string;
  merkle_root: string;
  verified: boolean;
}
export const provenance = {
  get: (event_id: string) => apiFetch<ProvenanceRecord>(`/provenance/${event_id}`),
};

// ── Pipeline ──────────────────────────────────────────────────────────────────
export interface SourceHealth {
  name: string;
  status: "online" | "degraded" | "offline";
  last_success: string | null;
  error: string | null;
  events_24h: number;
  next_run: string | null;
}
export interface TaskStatus {
  task_id: string;
  name: string;
  status: "PENDING" | "RUNNING" | "SUCCESS" | "FAILURE";
  started_at: string | null;
  completed_at: string | null;
  result: unknown;
}
export interface PipelineMetrics {
  events_total: number;
  events_24h: number;
  events_7d: number[];
  entity_breakdown: Record<string, number>;
  source_breakdown: Record<string, number>;
}
export const pipeline = {
  health: async (): Promise<SourceHealth[]> => {
    try {
      const res = await fetch(`${HEALTH_BASE}/sources`);
      if (!res.ok) return [];
      const data = await res.json();
      if (Array.isArray(data)) return data;
      if (data && typeof data === "object") {
        if (Array.isArray(data.sources)) return data.sources;
        if (data.sources && typeof data.sources === "object") {
          return Object.entries(data.sources).map(([name, s]: [string, any]) => ({
            name: s.source_id || name,
            status: s.status || (s.is_healthy === false ? "offline" : s.consecutive_failures > 0 ? "degraded" : "online"),
            last_success: s.last_success ?? null,
            error: s.last_error ?? s.error ?? null,
            events_24h: s.events_24h ?? s.total_successes ?? 0,
            next_run: s.next_run ?? null,
          }));
        }
      }
      return [];
    } catch {
      return [];
    }
  },
  metrics: () => apiFetch<PipelineMetrics>("/pipeline/metrics"),
  taskStatus: (id: string) => apiFetch<TaskStatus>(`/pipeline/task/${id}`),
  triggerSource: (source: string) =>
    apiFetch<{ task_id: string }>("/pipeline/collect", { method: "POST", body: JSON.stringify({ sources: [source] }) }),
  triggerAll: () =>
    apiFetch<{ task_id: string }>("/pipeline/collect/all", { method: "POST" }),
  blockchainLookup: (addresses: string[]) =>
    apiFetch<{ task_id: string }>("/pipeline/lookup/blockchain", {
      method: "POST",
      body: JSON.stringify({ addresses }),
    }),
  probeLookup: (urls: string[]) =>
    apiFetch<{ task_id: string }>("/pipeline/lookup/probe", {
      method: "POST",
      body: JSON.stringify({ urls }),
    }),
  crawl: (queries: string[]) =>
    apiFetch<{ task_id: string }>("/pipeline/crawl", {
      method: "POST",
      body: JSON.stringify({ queries }),
    }),
  runAnalytics: () =>
    apiFetch<{ task_id: string }>("/pipeline/analytics/run", { method: "POST" }),
  liveEvents: (limit = 50) =>
    apiFetch<{ events: Array<{ source: string; type: string; title: string; severity: string; timestamp: string; entities_found?: number }>; count: number }>(`/pipeline/events?limit=${limit}`),
  collectionRuns: () =>
    apiFetch<{ runs: Record<string, { source: string; completed_at: string; total_items: number; status: string }>; total_sources_run: number; total_items_collected: number }>("/pipeline/collection-runs"),
};

// ── Watchlist ─────────────────────────────────────────────────────────────────
export const watchlist = {
  add: (actor_id: string) =>
    apiFetch<{ ok: boolean }>("/watchlist", { method: "POST", body: JSON.stringify({ actor_id }) }),
};

// ── Exports ───────────────────────────────────────────────────────────────────

async function downloadFile(path: string, body: Record<string, unknown>, fallbackName: string) {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
    throw new Error("Session expired");
  }
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail?.detail ?? `HTTP ${res.status}`);
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition");
  let filename = fallbackName;
  if (disposition) {
    const match = disposition.match(/filename="?([^"]+)"?/);
    if (match) filename = match[1];
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export const exports_ = {
  dossier: (actor_id: string, format: "pdf" | "csv" | "json" = "pdf") =>
    downloadFile("/exports/dossier", { actor_id, format }, `dossier.${format}`),
  batch: (format: "csv" | "json" = "json", filter_status?: string) =>
    downloadFile("/exports/batch", { format, filter_status }, `netra_actors_export.${format}`),
  intel: (format: "csv" | "json" = "json") =>
    downloadFile("/exports/intel", { format, include_actors: true, include_entities: true }, `netra_intel_export.${format}`),
};
