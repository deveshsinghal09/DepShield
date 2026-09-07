"use client";

import { useMemo, useState } from "react";
import { Background, Controls, MarkerType, ReactFlow, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Check, CheckCircle2, Circle, LoaderCircle, Play, RotateCcw, TerminalSquare, TriangleAlert } from "lucide-react";
import type { Dependency } from "@/lib/types";
import { remediationLabel } from "@/lib/remediation";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";

type Replay = { demo: string; dependency: string; before: string | null; observed: string | null; vulnerable: boolean; cleanupVerified: boolean; safety: string };
type State = { kind: "idle" } | { kind: "loading" } | { kind: "success"; result: Replay } | { kind: "error"; message: string };
const nodeStyle = { background: "var(--card)", border: "1px solid var(--border)", borderRadius: 2, color: "var(--foreground)", padding: 14, width: 190, fontSize: 12 };

export function AttackReplayPanel({ dependency, scanId }: { dependency: Dependency; scanId: string }) {
  const [state, setState] = useState<State>({ kind: "idle" });
  const vulnerability = dependency.vulnerabilities.find((value) => value.cveAlias === "CVE-2019-10744" || value.id === "CVE-2019-10744") ?? dependency.vulnerabilities.toSorted((a, b) => b.cvss - a.cvss)[0];
  const supported = dependency.name === "lodash" && /^4\.17\.(?:11|21)$/.test(dependency.version);
  const ran = state.kind === "success";
  const remediated = dependency.version === "4.17.21";
  const label = remediationLabel(dependency);
  const nodes = useMemo<Node[]>(() => [
    { id: "input", position: { x: 0, y: 100 }, data: { label: "Fixed in-memory fixture" }, style: nodeStyle },
    { id: "route", position: { x: 250, y: 100 }, data: { label: "POST localhost:4100" }, style: nodeStyle },
    { id: "dependency", position: { x: 500, y: 100 }, data: { label: `${dependency.name}@${dependency.version}` }, style: { ...nodeStyle, border: `1px solid ${remediated ? "var(--safe)" : "var(--critical)"}` } },
    { id: "impact", position: { x: 750, y: 100 }, data: { label: ran ? (state.result.vulnerable ? "Marker observed" : "Marker blocked") : "Application object boundary" }, style: { ...nodeStyle, border: `1px solid ${ran ? state.result.vulnerable ? "var(--critical)" : "var(--safe)" : "var(--warning)"}` } },
  ], [dependency.name, dependency.version, ran, remediated, state]);
  const edges = [["input", "route"], ["route", "dependency"], ["dependency", "impact"]].map(([source, target], index) => ({ id: String(index), source, target, animated: ran, markerEnd: { type: MarkerType.ArrowClosed, color: "var(--primary)" }, style: { stroke: "var(--primary)", strokeWidth: 2 } }));

  async function run() {
    setState({ kind: "loading" });
    try {
      const response = await fetch("/api/attack-replay", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          scanId,
          dependencyName: dependency.name,
          dependencyVersion: dependency.version,
          vulnerabilityId: vulnerability?.cveAlias ?? vulnerability?.id ?? "CVE-2019-10744",
        }),
      });
      const body = await response.json() as { data?: Replay; error?: { message?: string } };
      if (!response.ok || !body.data) throw new Error(body.error?.message ?? "The replay did not complete.");
      setState({ kind: "success", result: body.data });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "The replay did not complete." });
    }
  }

  const output = state.kind === "success"
    ? `[safe-demo] Fixed fixture created in memory\n[trace] POST /demo/prototype-pollution on 127.0.0.1:4100\n[trace] Fixture dependency: ${state.result.dependency}\n[evidence] ${state.result.demo}${vulnerability?.cvssAvailable !== false && vulnerability ? ` · CVSS ${vulnerability.cvss.toFixed(1)}` : ""}\n[result] Prototype marker observable: ${state.result.vulnerable ? "YES" : "NO"}\n[cleanup] Temporary marker removed: ${state.result.cleanupVerified ? "YES" : "NO"}\n[safety] ${state.result.safety}\n[interpretation] ${state.result.vulnerable ? "Expected historical behavior was observed locally." : "The same fixed proof did not reproduce the historical marker behavior."}`
    : state.kind === "loading"
      ? "[safe-demo] Contacting the fixed localhost fixture…"
      : state.kind === "error"
        ? `[error] ${state.message}\n[recovery] Run npm run demo:install, then npm run demo:start in another PowerShell window.`
        : "Ready. No request has been sent. The replay cannot accept a target, payload, URL, path, or shell command.";
  const stages = [
    ["Dependency detected", true],
    ["CVE selected", Boolean(vulnerability) || remediated],
    ["Installed version recorded", true],
    ["Fixed safe proof prepared", supported],
    ["Local replay executed", ran],
    ["Behavior observation recorded", ran],
    ["Upgrade applied manually", remediated],
    ["Same replay repeated", remediated && ran],
    ["Difference recorded", remediated && ran],
  ] as const;

  return <section className="space-y-6" data-ui="attack-replay"><div className="flex items-start gap-3 border border-warning bg-warning/5 p-4"><TriangleAlert className="mt-0.5 shrink-0 text-warning" size={18}/><div><span className="hud-label text-warning">{"// LOCAL SAFETY BOUNDARY"}</span><p className="mt-1 text-sm"><b>Isolated teaching fixture only.</b> Replay sends one fixed, non-destructive proof to <span className="data">127.0.0.1:4100</span>. It accepts no target, payload, URL, path, or shell command and remains disabled in production.</p></div></div><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center"><div className="flex flex-wrap items-center gap-2"><Badge tone="neutral">Isolated local demo</Badge><Badge tone={vulnerability?.severity === "unknown" ? "neutral" : vulnerability?.severity ?? "safe"}>{vulnerability?.cveAlias ?? vulnerability?.id ?? "No active CVE"}</Badge><span className="data text-xs text-muted-foreground">{dependency.name}@{dependency.version}</span></div><Button onClick={ran ? () => setState({ kind: "idle" }) : run} disabled={!supported || state.kind === "loading"}>{state.kind === "loading" ? <LoaderCircle className="animate-spin" size={15} /> : ran ? <RotateCcw size={15} /> : <Play size={15} />}{state.kind === "loading" ? "Running fixed proof…" : ran ? "Reset replay" : "Run safe replay"}</Button></div>{!supported ? <div role="status" className="surface surface-outline flex gap-3 border-warning p-4 text-sm"><TriangleAlert className="shrink-0 text-warning" size={18} /><p>This fixed replay supports only the teaching fixture versions <b>lodash@4.17.11</b> and <b>lodash@4.17.21</b>. It cannot accept arbitrary dependencies or targets.</p></div> : null}<ol className="surface surface-outline grid gap-px overflow-hidden bg-border sm:grid-cols-3" aria-label="Attack Replay verification stages">{stages.map(([title, complete], index) => <li key={title} className="flex gap-3 bg-card p-4"><span className={`grid size-6 shrink-0 place-items-center rounded-full ${complete ? "bg-safe/10 text-safe" : "bg-secondary text-muted-foreground"}`}>{complete ? <Check size={13} /> : <Circle size={11} />}</span><div><span className="data text-xs text-muted-foreground">STAGE {index + 1}</span><p className="mt-1 text-xs font-semibold">{title}</p></div></li>)}</ol><div className="h-[320px] overflow-hidden rounded-[2px] border bg-background sm:h-[390px]" data-ui="attack-replay-graph"><ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.4}><Background color="var(--border)" gap={28} size={1} /><Controls showInteractive={false} /></ReactFlow></div><div className="surface surface-outline overflow-hidden"><div className="flex items-center gap-2 border-b px-4 py-3 text-xs text-muted-foreground"><TerminalSquare size={14} />Local replay result</div><pre aria-live="polite" className={`scrollbar min-h-44 overflow-auto whitespace-pre-wrap p-5 font-mono text-xs leading-6 ${state.kind === "error" ? "text-destructive" : "text-muted-foreground"}`}>{output}</pre></div><div className="flex items-start gap-3 border border-safe/30 bg-safe/5 p-4 text-sm"><CheckCircle2 className="mt-0.5 shrink-0 text-safe" size={18} /><div><b>{label ?? (remediated ? "Remediation verified by rescan" : "Recommended remediation")}</b><p className="mt-1 text-muted-foreground">{remediated ? "This scan records lodash@4.17.21 with no active historical finding. Repeat the same local proof to observe the changed behavior." : "Run npm run demo:remediate, restart the fixture, scan its folder again, then compare the two persisted scans."}</p></div></div></section>;
}
