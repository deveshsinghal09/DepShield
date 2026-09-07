"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import {
  ArrowLeftRight,
  Beaker,
  BookOpenCheck,
  GitBranch,
  History,
  LayoutDashboard,
  Menu,
  Network,
  PackageSearch,
  ScanLine,
  ScrollText,
  ShieldCheck,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { AnalystDrawer } from "./analyst-drawer";
import { ScanButton } from "./scan-button";
import { Sheet } from "./ui/sheet";

const nav = [
  { index: "00", href: "/scan", label: "Scan project", icon: ScanLine },
  { index: "01", href: "/", label: "Overview", icon: LayoutDashboard },
  { index: "02", href: "/dependencies", label: "Dependencies", icon: PackageSearch },
  { index: "03", href: "/attack-paths", label: "Attack paths", icon: GitBranch },
  { index: "04", href: "/remediation", label: "Upgrades", icon: Beaker },
  { index: "05", href: "/attack-replay", label: "Attack replay", icon: Network },
  { index: "06", href: "/comparison", label: "Compare", icon: ArrowLeftRight },
  { index: "07", href: "/history", label: "Scan history", icon: History },
  { index: "08", href: "/policies", label: "Policies", icon: BookOpenCheck },
  { index: "09", href: "/story", label: "Reports", icon: ScrollText },
];

type NavigationRailProps = {
  path: string;
  withScan: (href: string) => string;
  mobile?: boolean;
  onNavigate?: () => void;
  closeButtonRef?: React.RefObject<HTMLButtonElement | null>;
};

function NavigationRail({ path, withScan, mobile = false, onNavigate, closeButtonRef }: NavigationRailProps) {
  return (
    <aside
      className={cn(
        "navigation-rail h-full w-full flex-col border-r bg-[var(--rail)]",
        mobile ? "flex" : "sticky top-0 hidden h-screen lg:flex",
      )}
      aria-label={mobile ? "Mobile DepShield navigation" : "DepShield navigation"}
    >
      {mobile ? <h2 id="mobile-navigation-title" className="sr-only">Primary navigation</h2> : null}
      <div className="flex min-h-20 items-center justify-between border-b px-4">
        <Link href={withScan("/")} prefetch={false} className="flex items-center gap-3" onClick={onNavigate}>
          <span className="hud-panel grid size-10 place-items-center border border-primary text-primary"><ShieldCheck size={19} strokeWidth={1.6} /></span>
          <span className="rail-brand-copy">
            <b className="block text-base font-black tracking-[-.03em]">DepShield <span className="text-primary">AI</span></b>
            <small className="hud-label block">Dependency defence</small>
          </span>
        </Link>
        {mobile ? (
          <button ref={closeButtonRef} className="border p-2 text-muted-foreground hover:border-primary hover:text-primary" aria-label="Close navigation" onClick={onNavigate}>
            <X size={18} />
          </button>
        ) : null}
      </div>
      <nav aria-label="Primary" className="scrollbar min-h-0 flex-1 overflow-y-auto py-3">
        {nav.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? path === href : path.startsWith(href);
          return (
            <Link
              key={href}
              href={withScan(href)}
              prefetch={false}
              onClick={onNavigate}
              aria-current={active ? "page" : undefined}
              className={cn(
                "rail-link group flex flex-col items-center gap-2 border-l px-2 py-3 text-[10px] text-muted-foreground transition-colors duration-200 hover:border-foreground hover:bg-card hover:text-foreground",
                active ? "border-primary bg-card text-foreground" : "border-transparent",
              )}
            >
              <Icon size={21} strokeWidth={1.3} className={active ? "text-primary" : "opacity-60 group-hover:opacity-100"} />
              <span className="text-center">{label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="border-t px-2 py-4 text-center data text-[9px] text-muted-foreground">DEPSHIELD</div>
    </aside>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scan");
  const scanWorkspace = path === "/scan";
  const landingWorkspace = path === "/" && !scanId;
  const [open, setOpen] = useState(false);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const media = window.matchMedia("(min-width: 1024px)");
    const closeOnDesktop = (event: MediaQueryListEvent) => {
      if (event.matches) setOpen(false);
    };
    media.addEventListener("change", closeOnDesktop);
    return () => media.removeEventListener("change", closeOnDesktop);
  }, []);

  const withScan = (href: string) => {
    if (!scanId || href === "/history" || href === "/comparison" || href === "/scan") return href;
    return `${href}?scan=${encodeURIComponent(scanId)}`;
  };

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[96px_minmax(0,1fr)]" data-ui="app-shell">
      <NavigationRail path={path} withScan={withScan} />
      <Sheet
        id="primary-navigation-mobile"
        open={open}
        onOpenChange={setOpen}
        labelledBy="mobile-navigation-title"
        side="left"
        initialFocusRef={closeButtonRef}
        panelClassName="max-w-[280px]"
        dataUi="mobile-navigation"
      >
        <NavigationRail
          path={path}
          withScan={withScan}
          mobile
          onNavigate={() => setOpen(false)}
          closeButtonRef={closeButtonRef}
        />
      </Sheet>
      <main className="min-w-0">
        <header className={cn("sticky top-0 z-20 flex h-14 items-center justify-between border-b bg-background px-4 sm:px-6 lg:px-8", landingWorkspace && "lg:hidden")}>
          <button
            className="border p-2 text-muted-foreground hover:border-primary hover:text-primary lg:hidden"
            aria-label="Open navigation"
            aria-controls="primary-navigation-mobile"
            aria-expanded={open}
            onClick={() => setOpen(true)}
          >
            <Menu size={19} />
          </button>
          {scanWorkspace ? (
            <span className="text-sm text-muted-foreground">New project scan</span>
          ) : (
            <>
              <Link href="/" className="text-sm font-semibold">DepShield <span className="text-muted-foreground">/ Dependency security</span></Link>
              <div className="flex items-center gap-2"><AnalystDrawer /><ScanButton /></div>
            </>
          )}
        </header>
        <div className={landingWorkspace ? "p-2 sm:p-3" : scanWorkspace ? "max-w-none p-0" : "mx-auto max-w-[1680px] p-4 sm:p-6 lg:p-8"}>{children}</div>
      </main>
    </div>
  );
}
