"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

interface NavItem {
  href: string;
  icon: string;
  label: string;
  badge?: string | number;
  badgeVariant?: "default" | "warn" | "error" | "active";
  locked?: boolean;
}

const navItems: NavItem[] = [
  { href: "/dashboard", icon: "dashboard", label: "Overview" },
  { href: "/actors", icon: "person_alert", label: "Actors", badge: "42" },
  { href: "/graph", icon: "hub", label: "Graph Explorer" },
  { href: "/search", icon: "search", label: "Search" },
];

const monitorItems: NavItem[] = [
  { href: "/alerts", icon: "notifications_active", label: "Alerts", badge: "5", badgeVariant: "error" },
  { href: "/pipeline", icon: "account_tree", label: "Pipeline" },
];

export default function Sidebar() {
  const pathname = usePathname();

  const isActive = (href: string) => pathname === href || pathname.startsWith(href + "/");

  const itemClass = (href: string) =>
    isActive(href)
      ? "flex items-center justify-between text-primary font-bold border-l-2 border-cerulean bg-surface-container-low pl-3 py-2 rounded-r-lg transition-all font-label-ui text-label-ui"
      : "flex items-center justify-between text-ash hover:text-ink-black hover:bg-surface-container pl-3 py-2 rounded-lg transition-colors duration-100 font-label-ui text-label-ui";

  return (
    <aside className="fixed top-0 left-0 h-screen w-[220px] bg-paper border-r border-mist flex flex-col justify-between py-space-md px-space-sm z-30 select-none">
      <div className="flex flex-col gap-y-5">
        {/* Brand */}
        <div className="px-3 pt-2">
          <div className="flex items-center gap-2.5 mb-0.5">
            <div className="w-6 h-6 rounded border border-graphite flex items-center justify-center bg-paper text-primary font-code-default text-sm font-bold shrink-0">
              Ψ
            </div>
            <span className="font-headline-sub text-headline-sub text-primary tracking-tight font-bold">NETRA</span>
          </div>
          <p className="font-code-compact text-code-compact text-ash tracking-tight">Threat Dossier Archive</p>
        </div>

        {/* New Dossier CTA */}
        <div className="px-2">
          <button className="w-full h-9 bg-primary-container hover:bg-twilight text-paper font-label-ui text-label-ui rounded-lg flex items-center justify-center gap-1.5 transition-colors duration-100">
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>add</span>
            <span>New Dossier</span>
          </button>
        </div>

        {/* Investigation Suite */}
        <div>
          <div className="px-3 pb-2">
            <h2 className="font-label-uppercase text-label-uppercase text-ash">INVESTIGATION SUITE</h2>
          </div>
          <nav className="flex flex-col gap-0.5">
            {navItems.map((item) => (
              <Link key={item.href} href={item.href} className={itemClass(item.href)} title={item.label}>
                <div className="flex items-center gap-2.5">
                  <span
                    className={`material-symbols-outlined text-[19px] ${isActive(item.href) ? "text-cerulean" : ""}`}
                    style={isActive(item.href) ? { fontVariationSettings: "'FILL' 1" } : {}}
                  >
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </div>
                {item.badge && !isActive(item.href) && (
                  <span className="text-[11px] font-code-compact px-1.5 py-0.5 rounded bg-surface-container text-charcoal border border-mist mr-1">
                    {item.badge}
                  </span>
                )}
                {isActive(item.href) && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cerulean mr-2" />
                )}
              </Link>
            ))}
          </nav>
        </div>

        {/* Divider */}
        <div className="h-[1px] bg-mist mx-2" />

        {/* Monitoring & Ingest */}
        <div>
          <div className="px-3 pb-2">
            <h2 className="font-label-uppercase text-label-uppercase text-ash">MONITORING &amp; INGEST</h2>
          </div>
          <nav className="flex flex-col gap-0.5">
            {monitorItems.map((item) => (
              <Link
                key={item.href}
                href={item.locked ? "#" : item.href}
                className={
                  item.locked
                    ? "flex items-center justify-between text-ash/60 hover:text-ash pl-3 py-2 rounded-lg font-label-ui text-label-ui cursor-not-allowed"
                    : itemClass(item.href)
                }
                title={item.label}
              >
                <div className="flex items-center gap-2.5">
                  <span
                    className={`material-symbols-outlined text-[19px] ${isActive(item.href) ? "text-cerulean" : ""}`}
                    style={isActive(item.href) ? { fontVariationSettings: "'FILL' 1" } : {}}
                  >
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </div>
                {item.badge && !isActive(item.href) && !item.locked && (
                  <span className="text-[11px] font-code-compact px-1.5 py-0.5 rounded bg-error-container text-severity-critical font-medium mr-1">
                    {item.badge}
                  </span>
                )}
                {item.locked && (
                  <span className="material-symbols-outlined text-fog text-[15px] mr-1">lock</span>
                )}
                {isActive(item.href) && !item.locked && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cerulean mr-2" />
                )}
              </Link>
            ))}
          </nav>
        </div>
      </div>

      {/* Bottom: session + settings */}
      <div className="space-y-3 pt-4 border-t border-mist px-2">
        <div className="p-2.5 rounded-lg bg-surface-container-low border border-mist">
          <div className="flex items-center justify-between text-[11px] font-label-uppercase text-ash mb-1">
            <span>SESSION ENCLAVE</span>
            <span className="w-1.5 h-1.5 rounded-full bg-status-live" />
          </div>
          <div className="text-[12px] font-code-compact text-charcoal truncate">node-sig: 7fa9..c804</div>
          <div className="text-[10px] font-body-caption text-ash mt-0.5">TLS 1.3 · Ephemeral Key</div>
        </div>
        <div className="flex items-center justify-between text-ash text-[12px] px-1">
          <a href="#" className="hover:text-ink-black flex items-center gap-1">
            <span className="material-symbols-outlined text-[15px]">settings</span>
            <span>Settings</span>
          </a>
          <a href="#" className="hover:text-ink-black flex items-center gap-1">
            <span className="material-symbols-outlined text-[15px]">menu_book</span>
            <span>Docs</span>
          </a>
        </div>
      </div>
    </aside>
  );
}
