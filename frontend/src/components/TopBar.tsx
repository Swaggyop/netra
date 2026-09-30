"use client";
import { useRouter } from "next/navigation";
import { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { clearToken, exports_ as exportsApi } from "@/lib/api";

interface TopBarProps {
  alertCount?: number;
}

type ExportFormat = "json" | "csv" | "pdf";
type ExportDataType = "intel" | "actors" | "dossier";

interface ExportOption {
  key: ExportDataType;
  label: string;
  description: string;
  icon: string;
  formats: ExportFormat[];
}

const exportOptions: ExportOption[] = [
  {
    key: "intel",
    label: "Full Intel Package",
    description: "Actors + entities + relations",
    icon: "package_2",
    formats: ["json", "csv"],
  },
  {
    key: "actors",
    label: "Actor Registry",
    description: "All tracked actors with metadata",
    icon: "groups",
    formats: ["json", "csv"],
  },
  {
    key: "dossier",
    label: "Active Dossier (PDF)",
    description: "Formatted threat dossier report",
    icon: "description",
    formats: ["pdf", "json"],
  },
];

const formatMeta: Record<ExportFormat, { label: string; icon: string; color: string }> = {
  json: { label: "JSON",  icon: "data_object",  color: "text-cerulean" },
  csv:  { label: "CSV",   icon: "table_chart",   color: "text-status-live" },
  pdf:  { label: "PDF",   icon: "picture_as_pdf", color: "text-severity-high" },
};

export default function TopBar({ alertCount = 0 }: TopBarProps) {
  const router = useRouter();
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportFeedback, setExportFeedback] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setShowExportMenu(false);
      }
    };
    if (showExportMenu) document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showExportMenu]);

  const handleExport = async (dataType: ExportDataType, format: ExportFormat) => {
    setExporting(true);
    setExportFeedback(`Exporting ${dataType} as ${format.toUpperCase()}…`);
    try {
      if (dataType === "intel") {
        await exportsApi.intel(format as "csv" | "json" | "pdf");
      } else if (dataType === "actors") {
        await exportsApi.batch(format as "csv" | "json");
      } else if (dataType === "dossier") {
        await exportsApi.intel(format as "csv" | "json" | "pdf");
      }
      setExportFeedback(`✓ ${dataType} exported as ${format.toUpperCase()}`);
    } catch (err) {
      setExportFeedback(`✗ Export failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    }
    setExporting(false);
    setShowExportMenu(false);
    setTimeout(() => setExportFeedback(null), 3000);
  };

  const handleLogout = () => {
    clearToken();
    router.push("/login");
  };

  return (
    <>
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
          {/* Export Intel — with dropdown */}
          <div className="relative" ref={menuRef}>
            <button
              onClick={() => setShowExportMenu(!showExportMenu)}
              className="hidden lg:inline-flex items-center gap-1.5 px-3 py-1.5 text-label-ui font-label-ui border border-cerulean text-cerulean rounded-lg hover:opacity-80 transition-opacity"
            >
              <span className="material-symbols-outlined text-[16px]">ios_share</span>
              <span>Export Intel</span>
              <span className="material-symbols-outlined text-[14px]">expand_more</span>
            </button>

            {/* Export dropdown menu */}
            {showExportMenu && (
              <div
                className="absolute right-0 top-full mt-2 w-[340px] bg-paper border border-mist rounded-xl shadow-editorial overflow-hidden"
                style={{ animation: "fadeUp 0.15s ease" }}
              >
                {/* Header */}
                <div className="px-4 py-3 border-b border-mist bg-surface-container-low">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-cerulean text-[16px]">download</span>
                    <span className="font-label-ui text-label-ui text-graphite font-semibold">Export Data</span>
                  </div>
                  <p className="font-body-caption text-ash mt-0.5">Choose data type and format</p>
                </div>

                {/* Options */}
                <div className="p-2">
                  {exportOptions.map((opt) => (
                    <div key={opt.key} className="mb-1 last:mb-0">
                      <div className="px-3 py-2.5 rounded-lg hover:bg-linen transition-colors">
                        {/* Data type row */}
                        <div className="flex items-center gap-2.5 mb-2">
                          <span className="material-symbols-outlined text-[18px] text-charcoal">{opt.icon}</span>
                          <div className="flex-1 min-w-0">
                            <div className="font-label-ui text-label-ui text-ink-black">{opt.label}</div>
                            <div className="text-[11px] font-body-caption text-ash">{opt.description}</div>
                          </div>
                        </div>

                        {/* Format buttons */}
                        <div className="flex items-center gap-2 ml-[30px]">
                          {opt.formats.map((fmt) => {
                            const meta = formatMeta[fmt];
                            return (
                              <button
                                key={fmt}
                                disabled={exporting}
                                onClick={() => handleExport(opt.key, fmt)}
                                className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-mist text-[12px] font-label-ui font-medium
                                  hover:border-charcoal hover:bg-surface-container-low transition-all disabled:opacity-50 ${meta.color}`}
                              >
                                <span className="material-symbols-outlined text-[13px]">{meta.icon}</span>
                                {meta.label}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                      {opt.key !== "dossier" && <div className="h-[1px] bg-mist mx-3" />}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

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

      {/* Export feedback toast */}
      {exportFeedback && (
        <div
          className="fixed top-20 right-6 z-50 px-4 py-3 bg-paper border border-mist rounded-xl shadow-editorial flex items-center gap-2"
          style={{ animation: "fadeUp 0.2s ease" }}
        >
          <span className={`material-symbols-outlined text-[16px] ${exportFeedback.startsWith("✓") ? "text-status-live" : exportFeedback.startsWith("✗") ? "text-severity-critical" : "text-cerulean"}`}>
            {exportFeedback.startsWith("✓") ? "check_circle" : exportFeedback.startsWith("✗") ? "error" : "downloading"}
          </span>
          <span className="font-code-compact text-code-compact text-charcoal">{exportFeedback}</span>
        </div>
      )}
    </>
  );
}
