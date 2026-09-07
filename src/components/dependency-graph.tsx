"use client";

import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { Dependency } from "@/lib/types";

function LedgerNode({ data }: { data: { label: string; meta: string; tone?: string } }) {
  return <div className="w-52 rounded-[2px] border bg-card p-3"><Handle type="target" position={Position.Left} /><span className="hud-label">EVIDENCE NODE</span><b className="mt-1 block truncate text-xs">{data.label}</b><span className={`data mt-1 block text-xs ${data.tone ?? "text-muted-foreground"}`}>{data.meta}</span><Handle type="source" position={Position.Right} /></div>;
}

const nodeTypes = { ledger: LedgerNode };

export function DependencyGraph({ dependency }: { dependency: Dependency }) {
  const sourcePath = dependency.reachability?.paths.toSorted((left, right) => left.nodes.length - right.nodes.length)[0];
  const chain = sourcePath?.nodes.length ? sourcePath.nodes : dependency.paths?.[0]?.nodes ?? dependency.path.split(" → ");
  const finding = dependency.vulnerabilities.toSorted((left, right) => right.cvss - left.cvss)[0];
  const labels = [...chain, ...(finding ? [finding.cveAlias ?? finding.id] : [])];
  const nodes: Node[] = labels.map((label, index) => ({
    id: `path-${index}`,
    type: "ledger",
    position: { x: index * 250, y: index % 2 ? 120 : 72 },
    data: {
      label,
      meta: meta(label, index, labels.length, dependency, sourcePath?.internetExposed ?? false),
      tone: index === labels.length - 1 && finding ? "text-destructive" : undefined,
    },
  }));
  const edges = nodes.slice(1).map((_, index) => ({
    id: `edge-${index}`,
    source: nodes[index].id,
    target: nodes[index + 1].id,
    markerEnd: { type: MarkerType.ArrowClosed, color: "var(--primary)" },
    style: { stroke: "var(--primary)", strokeWidth: 1.75 },
  }));
  return <div><div className="h-[400px] overflow-hidden rounded-[2px] border bg-background" data-ui="dependency-graph"><ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView minZoom={0.3} maxZoom={1.4}><Background color="var(--border)" gap={28} size={1} /><Controls showInteractive={false} /></ReactFlow></div><details className="mt-3 text-xs"><summary className="cursor-pointer font-semibold text-muted-foreground">Accessible graph transcript</summary><ol className="data mt-2 space-y-1 text-muted-foreground">{labels.map((label, index) => <li key={`${label}-${index}`}>{index + 1}. {label}</li>)}</ol></details></div>;
}

function meta(label: string, index: number, length: number, dependency: Dependency, exposed: boolean) {
  if (index === length - 1 && /^(CVE-|GHSA-)/i.test(label)) return `${dependency.vulnerabilities.length} merged finding${dependency.vulnerabilities.length === 1 ? "" : "s"}`;
  if (/^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s\//.test(label)) return exposed ? "Possibly internet-exposed route" : "Route evidence";
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(label)) return "Observed application module";
  if (label.includes("@")) return label.includes(`${dependency.name}@`) ? `${dependency.reachability?.status.replace("_", " ") ?? "Reachability unknown"}` : "Parent dependency";
  return index === 0 ? "Application evidence boundary" : "Evidence node";
}
