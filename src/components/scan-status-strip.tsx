import { Activity, Database, Radar, ShieldCheck } from "lucide-react";

export function ScanStatusStrip({ lastScanAt, project }: { lastScanAt?: string | null; project?: string | null }) {
  const items = [
    { label: "Engine", value: "Ready", icon: Activity },
    { label: "Advisories", value: "npm + OSV", icon: Radar },
    { label: "Evidence ledger", value: lastScanAt ? "Synced" : "Awaiting first scan", icon: Database },
    { label: "Project", value: project ?? "Not selected", icon: ShieldCheck },
  ];
  return (
    <div className="scrollbar flex min-w-0 overflow-x-auto border-t bg-background" data-ui="scan-status-strip">
      <div className="flex min-w-max flex-1">
        <div className="flex items-center gap-2 border-r px-4 py-3">
          <span className="status-ping size-2 bg-primary" aria-hidden="true" />
          <span className="hud-label text-primary">System ready</span>
        </div>
        {items.map(({ label, value, icon: Icon }) => (
          <div key={label} className="flex items-center gap-2 border-r px-4 py-3">
            <Icon aria-hidden="true" size={12} className="text-muted-foreground" />
            <span className="hud-label">{label}: <b className="font-medium text-foreground">{value}</b></span>
          </div>
        ))}
        <div className="flex items-center px-4 py-3">
          <span className="hud-label">Last scan: <b className="font-medium text-foreground">{lastScanAt ? formatTimestamp(lastScanAt) : "No saved scan"}</b></span>
        </div>
      </div>
    </div>
  );
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
    hour12: false,
  }).format(new Date(value)) + " UTC";
}
