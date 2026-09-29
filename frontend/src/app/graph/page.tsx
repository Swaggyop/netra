"use client";
import { useEffect, useRef, useState, useMemo, useCallback } from "react";
import AppLayout from "@/components/AppLayout";
import { actors, type GraphNode, type GraphEdge } from "@/lib/api";
import Link from "next/link";

interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
}

interface SimEdge extends GraphEdge {
  sourceNode?: SimNode;
  targetNode?: SimNode;
}

const KIND_COLORS: Record<string, string> = {
  Actor: "#1e293b",
  Wallet: "#b45309",
  PGPKey: "#15803d",
  PGP: "#15803d",
  Onion: "#7e22ce",
  Handle: "#0284c7",
  Domain: "#475569",
  IP: "#475569",
  Entity: "#64748b",
};

const KIND_DISPLAY: Record<string, string> = {
  Actor: "Threat Actor",
  Wallet: "Crypto Wallet",
  PGPKey: "PGP Key",
  PGP: "PGP Key",
  Onion: "Tor Onion",
  Handle: "Forum Handle",
  Domain: "Domain Name",
  IP: "IP Address",
  Entity: "Entity",
};

export default function GraphPage() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [rawNodes, setRawNodes] = useState<GraphNode[]>([]);
  const [rawEdges, setRawEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & State
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [activeTypes, setActiveTypes] = useState<Record<string, boolean>>({
    Actor: true,
    Wallet: true,
    PGPKey: true,
    Onion: true,
    Handle: true,
    Domain: true,
  });

  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<SimNode | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);

  // Camera
  const transformRef = useRef({ x: 0, y: 0, scale: 1 });
  const isDraggingRef = useRef(false);
  const dragStartRef = useRef({ x: 0, y: 0 });
  const draggedNodeRef = useRef<SimNode | null>(null);
  const animFrameRef = useRef<number | null>(null);

  // Graph Sim State
  const simNodesRef = useRef<SimNode[]>([]);
  const simEdgesRef = useRef<SimEdge[]>([]);

  // Fetch graph data
  const loadGraph = useCallback(() => {
    setLoading(true);
    setError(null);
    actors.overviewGraph(300)
      .then((data) => {
        const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
        const edges = Array.isArray(data?.edges) ? data.edges : (Array.isArray((data as any)?.relationships) ? (data as any).relationships : []);
        setRawNodes(nodes);
        setRawEdges(edges);
      })
      .catch((err) => {
        console.error("Failed to fetch graph data", err);
        setError("Failed to load knowledge graph. Please verify backend connectivity.");
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // Normalize kind helper
  const normalizeKind = (k: string): string => {
    if (k === "PGP") return "PGPKey";
    if (k === "IP") return "Domain";
    if (["Actor", "Wallet", "PGPKey", "Onion", "Handle", "Domain"].includes(k)) return k;
    return "Domain";
  };

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return rawNodes.filter((n) => {
      const norm = normalizeKind(n.kind);
      if (activeTypes[norm] === false) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const lbl = (n.label || "").toLowerCase();
        const id = (n.id || "").toLowerCase();
        return lbl.includes(q) || id.includes(q);
      }
      return true;
    });
  }, [rawNodes, activeTypes, searchQuery]);

  // Filtered edges
  const filteredEdges = useMemo(() => {
    const validIds = new Set(filteredNodes.map((n) => n.id));
    return rawEdges.filter((e) => validIds.has(e.source) && validIds.has(e.target));
  }, [rawEdges, filteredNodes]);

  // Setup simulation nodes & edges when filters or raw data change
  useEffect(() => {
    const width = containerRef.current?.clientWidth || 900;
    const height = containerRef.current?.clientHeight || 600;

    // Preserve existing positions if possible
    const existingMap = new Map<string, SimNode>();
    for (const sn of simNodesRef.current) {
      existingMap.set(sn.id, sn);
    }

    const simNodes: SimNode[] = filteredNodes.map((n, i) => {
      const existing = existingMap.get(n.id);
      const isActor = n.kind === "Actor";
      const radius = isActor ? 14 : 9;
      const color = KIND_COLORS[n.kind] || KIND_COLORS[normalizeKind(n.kind)] || "#64748b";

      if (existing) {
        return {
          ...n,
          x: existing.x,
          y: existing.y,
          vx: existing.vx * 0.5,
          vy: existing.vy * 0.5,
          radius,
          color,
        };
      }

      // Random circular initial placement around center
      const angle = (i / Math.max(1, filteredNodes.length)) * Math.PI * 2;
      const dist = isActor ? Math.random() * 150 + 40 : Math.random() * 260 + 120;
      return {
        ...n,
        x: width / 2 + Math.cos(angle) * dist + (Math.random() - 0.5) * 40,
        y: height / 2 + Math.sin(angle) * dist + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
        radius,
        color,
      };
    });

    const nodeMap = new Map<string, SimNode>(simNodes.map((sn) => [sn.id, sn]));

    const simEdges: SimEdge[] = filteredEdges
      .map((e) => ({
        ...e,
        sourceNode: nodeMap.get(e.source),
        targetNode: nodeMap.get(e.target),
      }))
      .filter((e): e is SimEdge & { sourceNode: SimNode; targetNode: SimNode } => !!(e.sourceNode && e.targetNode));

    simNodesRef.current = simNodes;
    simEdgesRef.current = simEdges;
  }, [filteredNodes, filteredEdges]);

  // Physics animation loop
  useEffect(() => {
    let active = true;

    const runPhysicsStep = (width: number, height: number) => {
      const nodes = simNodesRef.current;
      const edges = simEdgesRef.current;

      const cx = width / 2;
      const cy = height / 2;

      // 1. Center gravity
      for (const n of nodes) {
        const dx = cx - n.x;
        const dy = cy - n.y;
        n.vx += dx * 0.0008;
        n.vy += dy * 0.0008;
      }

      // 2. Node repulsion (Coulomb force)
      const count = nodes.length;
      for (let i = 0; i < count; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < count; j++) {
          const b = nodes[j];
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const distSq = dx * dx + dy * dy + 1;
          if (distSq < 90000) {
            const dist = Math.sqrt(distSq);
            const force = (a.radius + b.radius + 35) / distSq;
            const fx = (dx / dist) * force * 15;
            const fy = (dy / dist) * force * 15;
            a.vx -= fx;
            a.vy -= fy;
            b.vx += fx;
            b.vy += fy;
          }
        }
      }

      // 3. Edge spring attraction (Hooke's law)
      for (const e of edges) {
        if (!e.sourceNode || !e.targetNode) continue;
        const a = e.sourceNode;
        const b = e.targetNode;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const targetDist = 70;
        const force = (dist - targetDist) * 0.025;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx += fx;
        a.vy += fy;
        b.vx -= fx;
        b.vy -= fy;
      }

      // 4. Integrate velocity with damping
      for (const n of nodes) {
        if (draggedNodeRef.current === n) continue;
        n.vx *= 0.88;
        n.vy *= 0.88;
        n.x += n.vx;
        n.y += n.vy;
      }
    };

    const render = () => {
      if (!active) return;
      const canvas = canvasRef.current;
      const container = containerRef.current;
      if (!canvas || !container) {
        animFrameRef.current = requestAnimationFrame(render);
        return;
      }

      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const dpr = window.devicePixelRatio || 1;
      const width = container.clientWidth;
      const height = container.clientHeight;

      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
      }

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, width, height);

      // Run simulation step
      runPhysicsStep(width, height);

      // Apply pan & zoom
      const { x: panX, y: panY, scale } = transformRef.current;
      ctx.translate(panX, panY);
      ctx.scale(scale, scale);

      const nodes = simNodesRef.current;
      const edges = simEdgesRef.current;
      const highlightedNode = hoveredNode || selectedNode;

      // Draw subtle grid
      ctx.strokeStyle = "#e2e8f033";
      ctx.lineWidth = 1 / scale;
      const gridSize = 40;
      const startX = -panX / scale - 100;
      const endX = (width - panX) / scale + 100;
      const startY = -panY / scale - 100;
      const endY = (height - panY) / scale + 100;

      ctx.beginPath();
      for (let gx = Math.floor(startX / gridSize) * gridSize; gx <= endX; gx += gridSize) {
        ctx.moveTo(gx, startY);
        ctx.lineTo(gx, endY);
      }
      for (let gy = Math.floor(startY / gridSize) * gridSize; gy <= endY; gy += gridSize) {
        ctx.moveTo(startX, gy);
        ctx.lineTo(endX, gy);
      }
      ctx.stroke();

      // Draw edges
      for (const e of edges) {
        if (!e.sourceNode || !e.targetNode) continue;
        const a = e.sourceNode;
        const b = e.targetNode;

        const isConnected = highlightedNode && (a.id === highlightedNode.id || b.id === highlightedNode.id);
        const isDimmed = highlightedNode && !isConnected;

        ctx.strokeStyle = isConnected
          ? "#2563eb"
          : isDimmed
          ? "#cbd5e140"
          : "#cbd5e1";
        ctx.lineWidth = isConnected ? 2 / scale : 1 / scale;

        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();

        // Edge relation badge if connected or hovered
        if (isConnected) {
          const midX = (a.x + b.x) / 2;
          const midY = (a.y + b.y) / 2;
          ctx.font = `${Math.max(9, 10 / scale)}px sans-serif`;
          ctx.fillStyle = "#1e293b";
          ctx.textAlign = "center";
          ctx.fillText(e.relation || "LINK", midX, midY - 4);
        }
      }

      // Draw nodes
      for (const n of nodes) {
        const isSelected = selectedNode?.id === n.id;
        const isHovered = hoveredNode?.id === n.id;
        const isConnected = highlightedNode && edges.some(
          (e) => (e.sourceNode?.id === highlightedNode.id && e.targetNode?.id === n.id) ||
                 (e.targetNode?.id === highlightedNode.id && e.sourceNode?.id === n.id)
        );
        const isDimmed = highlightedNode && !isSelected && !isHovered && !isConnected;

        ctx.save();
        ctx.globalAlpha = isDimmed ? 0.25 : 1;

        // Selection ring
        if (isSelected || isHovered) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius + 6 / scale, 0, Math.PI * 2);
          ctx.fillStyle = isSelected ? "rgba(37, 99, 235, 0.15)" : "rgba(100, 116, 139, 0.15)";
          ctx.fill();
          ctx.strokeStyle = isSelected ? "#2563eb" : "#64748b";
          ctx.lineWidth = 2 / scale;
          ctx.stroke();
        }

        // Main node body
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.fill();
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 1.5 / scale;
        ctx.stroke();

        // Node label
        const displayLabel = n.label || n.id.slice(0, 8);
        const shortLabel = displayLabel.length > 18 ? displayLabel.slice(0, 16) + "…" : displayLabel;

        ctx.font = `${n.kind === "Actor" ? "bold " : ""}${Math.max(10, 11 / scale)}px sans-serif`;
        ctx.fillStyle = isSelected ? "#1d4ed8" : "#334155";
        ctx.textAlign = "center";
        ctx.fillText(shortLabel, n.x, n.y + n.radius + 12 / scale);

        ctx.restore();
      }

      ctx.restore();
      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);
    return () => {
      active = false;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [hoveredNode, selectedNode]);

  // Coordinate helper: screen to world
  const toWorld = useCallback((screenX: number, screenY: number) => {
    const { x: panX, y: panY, scale } = transformRef.current;
    return {
      x: (screenX - panX) / scale,
      y: (screenY - panY) / scale,
    };
  }, []);

  // Find node under cursor
  const findNodeAt = useCallback((screenX: number, screenY: number): SimNode | null => {
    const { x, y } = toWorld(screenX, screenY);
    const { scale } = transformRef.current;
    const nodes = simNodesRef.current;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = n.x - x;
      const dy = n.y - y;
      const hitRadius = (n.radius + 6) / Math.min(1, scale);
      if (dx * dx + dy * dy <= hitRadius * hitRadius) {
        return n;
      }
    }
    return null;
  }, [toWorld]);

  // Mouse / Pointer event handlers
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;

    const hit = findNodeAt(clientX, clientY);
    if (hit) {
      draggedNodeRef.current = hit;
      setSelectedNode(hit);
    } else {
      isDraggingRef.current = true;
      dragStartRef.current = { x: clientX - transformRef.current.x, y: clientY - transformRef.current.y };
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;

    if (draggedNodeRef.current) {
      const { x, y } = toWorld(clientX, clientY);
      draggedNodeRef.current.x = x;
      draggedNodeRef.current.y = y;
      draggedNodeRef.current.vx = 0;
      draggedNodeRef.current.vy = 0;
      return;
    }

    if (isDraggingRef.current) {
      transformRef.current.x = clientX - dragStartRef.current.x;
      transformRef.current.y = clientY - dragStartRef.current.y;
      return;
    }

    // Hover detection
    const hit = findNodeAt(clientX, clientY);
    setHoveredNode(hit);
    if (hit) {
      setTooltipPos({ x: clientX + 16, y: clientY + 16 });
    } else {
      setTooltipPos(null);
    }
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
    draggedNodeRef.current = null;
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;

    const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85;
    const oldScale = transformRef.current.scale;
    const newScale = Math.min(3.0, Math.max(0.2, oldScale * zoomFactor));

    // Zoom centered on cursor
    transformRef.current.x = clientX - (clientX - transformRef.current.x) * (newScale / oldScale);
    transformRef.current.y = clientY - (clientY - transformRef.current.y) * (newScale / oldScale);
    transformRef.current.scale = newScale;
  };

  // Zoom buttons
  const zoomIn = () => {
    const container = containerRef.current;
    if (!container) return;
    const cx = container.clientWidth / 2;
    const cy = container.clientHeight / 2;
    const oldScale = transformRef.current.scale;
    const newScale = Math.min(3.0, oldScale * 1.25);
    transformRef.current.x = cx - (cx - transformRef.current.x) * (newScale / oldScale);
    transformRef.current.y = cy - (cy - transformRef.current.y) * (newScale / oldScale);
    transformRef.current.scale = newScale;
  };

  const zoomOut = () => {
    const container = containerRef.current;
    if (!container) return;
    const cx = container.clientWidth / 2;
    const cy = container.clientHeight / 2;
    const oldScale = transformRef.current.scale;
    const newScale = Math.max(0.2, oldScale / 1.25);
    transformRef.current.x = cx - (cx - transformRef.current.x) * (newScale / oldScale);
    transformRef.current.y = cy - (cy - transformRef.current.y) * (newScale / oldScale);
    transformRef.current.scale = newScale;
  };

  const resetView = () => {
    transformRef.current = { x: 0, y: 0, scale: 1 };
  };

  // Connected neighbors for selected node
  const selectedNeighbors = useMemo(() => {
    if (!selectedNode) return [];
    const edges = simEdgesRef.current;
    const neighbors: { node: SimNode; relation: string; direction: "out" | "in" }[] = [];
    for (const e of edges) {
      if (e.sourceNode?.id === selectedNode.id && e.targetNode) {
        neighbors.push({ node: e.targetNode, relation: e.relation, direction: "out" });
      } else if (e.targetNode?.id === selectedNode.id && e.sourceNode) {
        neighbors.push({ node: e.sourceNode, relation: e.relation, direction: "in" });
      }
    }
    return neighbors;
  }, [selectedNode]);

  // Toggle node type filter
  const toggleType = (kind: string) => {
    setActiveTypes((prev) => ({ ...prev, [kind]: !prev[kind] }));
  };

  return (
    <AppLayout>
      <div className="flex gap-6 h-[calc(100vh-140px)]">
        {/* Left control panel */}
        <div className="w-[300px] shrink-0 bg-paper border border-mist rounded-xl p-5 shadow-editorial flex flex-col gap-4 overflow-y-auto custom-scroll">
          <div>
            <div className="flex items-center justify-between">
              <h2 className="font-headline-lg text-headline-lg text-graphite mb-0.5">Graph Explorer</h2>
              <button
                onClick={loadGraph}
                disabled={loading}
                title="Reload Graph"
                className="p-1 hover:bg-linen rounded text-ash hover:text-graphite transition-colors"
              >
                <span className={`material-symbols-outlined text-[18px] ${loading ? "animate-spin" : ""}`}>refresh</span>
              </button>
            </div>
            <p className="font-body-caption text-ash text-[12px]">Dynamic threat intelligence knowledge graph</p>
          </div>

          <div className="h-[1px] bg-mist" />

          {/* Search */}
          <div>
            <label className="text-[10px] font-label-uppercase text-ash tracking-wider block mb-1.5 font-semibold">SEARCH GRAPH</label>
            <div className="relative">
              <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-ash text-[16px]">search</span>
              <input
                className="w-full pl-8 pr-3 py-1.5 bg-linen border border-mist rounded-lg text-body-default font-body-default text-charcoal text-[13px] focus:outline-none focus:border-graphite"
                placeholder="Actor, wallet, onion…"
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-ash hover:text-graphite"
                >
                  <span className="material-symbols-outlined text-[14px]">close</span>
                </button>
              )}
            </div>
          </div>

          <div className="h-[1px] bg-mist" />

          {/* Node types filters */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-[10px] font-label-uppercase text-ash tracking-wider font-semibold">NODE TYPES</label>
              <button
                onClick={() => {
                  const allActive = Object.values(activeTypes).every(Boolean);
                  setActiveTypes({
                    Actor: !allActive,
                    Wallet: !allActive,
                    PGPKey: !allActive,
                    Onion: !allActive,
                    Handle: !allActive,
                    Domain: !allActive,
                  });
                }}
                className="text-[11px] text-cerulean hover:underline font-label-ui"
              >
                Toggle All
              </button>
            </div>
            <div className="space-y-2">
              {[
                { key: "Actor", label: "Actors", color: KIND_COLORS.Actor },
                { key: "Wallet", label: "Wallets", color: KIND_COLORS.Wallet },
                { key: "PGPKey", label: "PGP Keys", color: KIND_COLORS.PGPKey },
                { key: "Onion", label: "Onion Addresses", color: KIND_COLORS.Onion },
                { key: "Handle", label: "Handles", color: KIND_COLORS.Handle },
                { key: "Domain", label: "IPs / Domains", color: KIND_COLORS.Domain },
              ].map((nt) => {
                const count = rawNodes.filter((n) => normalizeKind(n.kind) === nt.key).length;
                const isChecked = activeTypes[nt.key] ?? true;
                return (
                  <label key={nt.key} className="flex items-center justify-between cursor-pointer group py-0.5">
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleType(nt.key)}
                        className="rounded border-mist text-twilight focus:ring-0 cursor-pointer"
                      />
                      <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: nt.color }} />
                      <span className={`font-label-ui text-label-ui text-[13px] ${isChecked ? "text-charcoal font-medium" : "text-ash"}`}>
                        {nt.label}
                      </span>
                    </div>
                    <span className="font-code-compact text-[11px] text-ash bg-surface-container px-1.5 py-0.5 rounded">
                      {count}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="h-[1px] bg-mist" />

          {/* Quick controls */}
          <div>
            <label className="text-[10px] font-label-uppercase text-ash tracking-wider block mb-2 font-semibold">VIEW CONTROLS</label>
            <div className="grid grid-cols-3 gap-1.5">
              <button
                onClick={zoomIn}
                className="px-2 py-1.5 bg-linen hover:bg-mist/50 border border-mist rounded text-body-caption font-label-ui text-charcoal flex items-center justify-center gap-1"
              >
                <span className="material-symbols-outlined text-[16px]">zoom_in</span> In
              </button>
              <button
                onClick={zoomOut}
                className="px-2 py-1.5 bg-linen hover:bg-mist/50 border border-mist rounded text-body-caption font-label-ui text-charcoal flex items-center justify-center gap-1"
              >
                <span className="material-symbols-outlined text-[16px]">zoom_out</span> Out
              </button>
              <button
                onClick={resetView}
                className="px-2 py-1.5 bg-linen hover:bg-mist/50 border border-mist rounded text-body-caption font-label-ui text-charcoal flex items-center justify-center gap-1"
              >
                <span className="material-symbols-outlined text-[16px]">center_focus_strong</span> Reset
              </button>
            </div>
          </div>

          {/* Stats summary footer */}
          <div className="mt-auto pt-4 border-t border-mist">
            <div className="flex items-center justify-between text-[11px] font-code-compact text-ash">
              <span>{filteredNodes.length} nodes · {filteredEdges.length} edges</span>
              <span className="w-2 h-2 rounded-full bg-status-live inline-block" title="Neo4j Live" />
            </div>
          </div>
        </div>

        {/* Graph canvas container */}
        <div
          ref={containerRef}
          className="flex-1 bg-background border border-mist rounded-xl overflow-hidden relative shadow-editorial select-none"
        >
          {loading ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center bg-background/80 z-20">
              <span className="material-symbols-outlined text-[48px] text-twilight animate-spin mb-3">progress_activity</span>
              <p className="font-body-reading text-charcoal font-medium">Querying Neo4j Knowledge Graph…</p>
              <p className="font-body-caption text-ash text-[12px] mt-1">Retrieving nodes &amp; relational links</p>
            </div>
          ) : error ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center z-20">
              <span className="material-symbols-outlined text-[48px] text-severity-critical mb-3">error</span>
              <p className="font-headline-sub text-headline-sub text-graphite mb-1">Graph Unavailable</p>
              <p className="font-body-reading text-ash text-[13px] max-w-sm mb-4">{error}</p>
              <button
                onClick={loadGraph}
                className="px-4 py-2 bg-paper border border-mist rounded-lg text-body-default font-label-ui text-charcoal hover:bg-linen shadow-sm"
              >
                Retry Connection
              </button>
            </div>
          ) : filteredNodes.length === 0 ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center z-20">
              <span className="material-symbols-outlined text-[48px] text-ash mb-3">filter_alt_off</span>
              <p className="font-headline-sub text-headline-sub text-graphite mb-1">No Matching Nodes</p>
              <p className="font-body-reading text-ash text-[13px] max-w-sm mb-4">
                No nodes match the selected filters or search query. Try enabling more node types.
              </p>
              <button
                onClick={() => {
                  setSearchQuery("");
                  setActiveTypes({
                    Actor: true,
                    Wallet: true,
                    PGPKey: true,
                    Onion: true,
                    Handle: true,
                    Domain: true,
                  });
                }}
                className="px-4 py-1.5 bg-paper border border-mist rounded-lg text-body-caption font-label-ui text-charcoal hover:bg-linen"
              >
                Reset Filters
              </button>
            </div>
          ) : null}

          {/* Interactive Canvas */}
          <canvas
            ref={canvasRef}
            className="w-full h-full cursor-grab active:cursor-grabbing block"
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
          />

          {/* Floating Tooltip on Hover */}
          {tooltipPos && hoveredNode && !selectedNode && (
            <div
              className="absolute z-30 pointer-events-none bg-paper/95 backdrop-blur border border-mist rounded-lg p-2.5 shadow-xl text-left max-w-xs"
              style={{ left: tooltipPos.x, top: tooltipPos.y }}
            >
              <div className="flex items-center gap-1.5 mb-1">
                <span
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{ backgroundColor: hoveredNode.color }}
                />
                <span className="text-[10px] font-label-uppercase tracking-wider font-semibold text-ash">
                  {KIND_DISPLAY[hoveredNode.kind] || hoveredNode.kind}
                </span>
              </div>
              <p className="font-code-default text-[12px] text-graphite font-bold break-all">
                {hoveredNode.label}
              </p>
              <p className="text-[10px] font-code-compact text-ash mt-1">
                Click node to open inspector
              </p>
            </div>
          )}

          {/* Selected Node Inspector Drawer (Right Slide-in) */}
          {selectedNode && (
            <div className="absolute top-4 right-4 bottom-4 w-[340px] bg-paper/95 backdrop-blur border border-mist rounded-xl shadow-2xl p-5 flex flex-col z-30 overflow-y-auto custom-scroll animate-in fade-in slide-in-from-right-4 duration-200">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span
                    className="w-3 h-3 rounded-full shrink-0"
                    style={{ backgroundColor: selectedNode.color }}
                  />
                  <span className="text-[11px] font-label-uppercase tracking-wider font-bold text-ash">
                    {KIND_DISPLAY[selectedNode.kind] || selectedNode.kind}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 text-ash hover:text-graphite rounded hover:bg-linen transition-colors"
                >
                  <span className="material-symbols-outlined text-[18px]">close</span>
                </button>
              </div>

              <h3 className="font-headline-sub text-headline-sub text-graphite font-bold break-all mb-2">
                {selectedNode.label}
              </h3>

              <div className="space-y-2 mb-4 bg-linen p-3 rounded-lg border border-mist text-[12px]">
                <div>
                  <span className="text-ash block text-[10px] font-label-uppercase font-semibold">Node ID</span>
                  <span className="font-code-compact text-charcoal break-all">{selectedNode.id}</span>
                </div>
                {Boolean(selectedNode.properties?.category) && (
                  <div>
                    <span className="text-ash block text-[10px] font-label-uppercase font-semibold">Category</span>
                    <span className="font-label-ui text-charcoal">{String(selectedNode.properties?.category)}</span>
                  </div>
                )}
                {Boolean(selectedNode.properties?.status) && (
                  <div>
                    <span className="text-ash block text-[10px] font-label-uppercase font-semibold">Status</span>
                    <span className="font-label-ui text-charcoal capitalize">{String(selectedNode.properties?.status)}</span>
                  </div>
                )}
                {Boolean(selectedNode.properties?.first_seen) && (
                  <div>
                    <span className="text-ash block text-[10px] font-label-uppercase font-semibold">First Seen</span>
                    <span className="font-code-compact text-charcoal">
                      {new Date(String(selectedNode.properties?.first_seen)).toLocaleDateString()}
                    </span>
                  </div>
                )}
              </div>

              {/* Actor profile link button */}
              {selectedNode.kind === "Actor" && (
                <Link
                  href={`/actors/${selectedNode.id}`}
                  className="mb-4 w-full py-2 bg-twilight hover:opacity-90 text-white rounded-lg text-center font-label-ui text-[13px] flex items-center justify-center gap-2 shadow-sm transition-opacity"
                >
                  <span className="material-symbols-outlined text-[16px]">fingerprint</span>
                  Open Threat Dossier
                </Link>
              )}

              {/* Connected Relationships */}
              <div className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-label-uppercase font-semibold text-ash tracking-wider">
                    CONNECTED RELATIONS ({selectedNeighbors.length})
                  </span>
                </div>

                {selectedNeighbors.length === 0 ? (
                  <p className="text-[12px] text-ash italic">No direct edges visible in current view</p>
                ) : (
                  <div className="space-y-1.5">
                    {selectedNeighbors.map((nbr, idx) => (
                      <button
                        key={`${nbr.node.id}-${idx}`}
                        onClick={() => setSelectedNode(nbr.node)}
                        className="w-full text-left p-2 rounded-lg bg-surface-container hover:bg-mist/60 border border-mist transition-colors flex items-center justify-between group"
                      >
                        <div className="flex items-center gap-2 min-w-0 pr-2">
                          <span
                            className="w-2 h-2 rounded-full shrink-0"
                            style={{ backgroundColor: nbr.node.color }}
                          />
                          <div className="min-w-0">
                            <span className="text-[12px] font-medium text-graphite block truncate group-hover:text-cerulean">
                              {nbr.node.label}
                            </span>
                            <span className="text-[10px] text-ash">
                              {nbr.direction === "out" ? "→" : "←"} {nbr.relation}
                            </span>
                          </div>
                        </div>
                        <span className="material-symbols-outlined text-ash text-[14px] shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                          chevron_right
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Canvas Floating Overlay Controls */}
          <div className="absolute bottom-4 left-4 bg-paper/90 backdrop-blur border border-mist rounded-lg px-3 py-1.5 flex items-center gap-3 shadow-md text-[12px] font-label-ui text-ash pointer-events-none">
            <span className="flex items-center gap-1">
              <kbd className="bg-linen border border-mist rounded px-1 text-[10px] font-code-compact">Drag</kbd> Pan
            </span>
            <span className="text-mist">|</span>
            <span className="flex items-center gap-1">
              <kbd className="bg-linen border border-mist rounded px-1 text-[10px] font-code-compact">Scroll</kbd> Zoom
            </span>
            <span className="text-mist">|</span>
            <span className="flex items-center gap-1">
              <kbd className="bg-linen border border-mist rounded px-1 text-[10px] font-code-compact">Click</kbd> Inspect
            </span>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
