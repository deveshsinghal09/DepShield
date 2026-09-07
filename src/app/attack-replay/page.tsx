import { PageHeader } from "@/components/page-header";
import { EmptyState, SavedScanUnavailable } from "@/components/empty-state";
import { FeatureUnavailable } from "@/components/feature-unavailable";
import { AttackReplayPanel } from "@/components/attack-replay-panel";
import { Button } from "@/components/ui/button";
import { getFeatureFlags } from "@/lib/feature-flags";
import { resolveSavedScan } from "@/server/scan-resolution";

export const dynamic = "force-dynamic";

export default async function AttackReplay({ searchParams }: { searchParams: Promise<{ scan?: string; dependency?: string }> }) {
  const query = await searchParams;
  if (!getFeatureFlags().attackReplay) {
    return <><PageHeader title="Attack Replay" description="A closed localhost verification environment with fixed input, route, and observable behavior." /><FeatureUnavailable feature="Attack Replay" description="Local replay is disabled here because it requires the fixed vulnerable-demo fixture on 127.0.0.1. No arbitrary target, payload, path, or command is accepted." flag="ENABLE_ATTACK_REPLAY" /></>;
  }
  const { scans, resolution } = resolveSavedScan(query.scan, (items) => items.find((item) => item.project === "depshield-vulnerable-demo") ?? items[0]);
  if (resolution.status === "missing") return <><PageHeader title="Attack Replay" description="A closed localhost verification environment: fixed input, fixed route, observable behavior, then a repeated proof after manual remediation." /><SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/attack-replay" /></>;
  const scan = resolution.scan;
  const candidates = scan?.items.filter((item) => item.vulnerabilities.length > 0 || item.name === "lodash").toSorted((left, right) => (left.name === "lodash" ? -1 : 0) - (right.name === "lodash" ? -1 : 0) || right.risk - left.risk) ?? [];
  const selected = candidates.find((item) => `${item.name}@${item.version}::${item.path}` === query.dependency) ?? candidates[0];
  const finding = selected?.vulnerabilities.find((value) => value.cveAlias === "CVE-2019-10744") ?? selected?.vulnerabilities[0];
  return <><PageHeader title="Attack Replay" description="A closed localhost verification environment: fixed input, fixed route, observable behavior, then a repeated proof after manual remediation." action={scan ? <form className="flex max-w-full flex-col gap-2 lg:flex-row"><select name="scan" defaultValue={scan.id} aria-label="Select replay scan" className="h-10 max-w-64 rounded-sm border bg-card px-3 text-sm">{scans.map((item) => <option key={item.id} value={item.id}>{item.project} · {new Date(item.createdAt).toLocaleString()}</option>)}</select>{selected ? <select name="dependency" defaultValue={`${selected.name}@${selected.version}::${selected.path}`} aria-label="Select dependency" className="h-10 max-w-64 rounded-sm border bg-card px-3 text-sm">{candidates.map((item) => <option key={`${item.name}@${item.version}-${item.path}`} value={`${item.name}@${item.version}::${item.path}`}>{item.name}@{item.version}</option>)}</select> : null}<Button variant="outline" type="submit">Load evidence</Button></form> : undefined} />{selected && scan ? <div className="space-y-6"><section className="surface surface-outline grid gap-px overflow-hidden bg-border md:grid-cols-3"><Step title="Evidence" value={finding ? `${finding.cveAlias ?? finding.id} · ${finding.cvssAvailable === false ? "CVSS unavailable" : `CVSS ${finding.cvss.toFixed(1)}`}` : "No active historical finding in this remediated scan"} /><Step title="Dependency path" value={selected.path} /><Step title="Recovery" value={selected.recommendation === "upgrade" ? `Pin ${selected.latest}, restart, and rescan` : selected.version === "4.17.21" ? "Fixed pin observed; repeat the same local proof" : "Review remediation evidence"} /></section><AttackReplayPanel dependency={selected} scanId={scan.id} /></div> : <EmptyState title="No dependency available for replay" description="Scan the vulnerable-demo folder before opening the isolated Attack Replay." />}</>;
}

function Step({ title, value }: { title: string; value: string }) { return <div className="min-w-0 bg-card p-5"><b className="text-xs text-primary">{title}</b><p className="data mt-2 break-words text-xs leading-5 text-muted-foreground">{value}</p></div>; }
