"use client";

import { useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { Crosshair, Filter, Info, ShieldAlert } from "lucide-react";
import type { AttackPath, Dependency, Vulnerability } from "@/lib/types";
import {
  orderAttackPathCandidates,
  resolveAttackPathCandidates,
  type AttackPathCandidate,
  type AttackPathOrder,
} from "@/lib/attack-path-view";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity";
import "@xyflow/react/dist/style.css";

type Filters = {
  critical: boolean;
  reachable: boolean;
  exposed: boolean;
  direct: boolean;
  transitive: boolean;
  fix: boolean;
};

type LedgerNodeData = {
  label: string;
  meta: string;
  kind: string;
  risk?: number;
  riskLabel?: string;
  evidence: string;
};

function AttackNode({ data }: NodeProps<Node<LedgerNodeData>>) {
  const tone = data.risk !== undefined && data.risk >= 80
    ? "text-destructive"
    : data.kind === "cve"
      ? "text-warning"
      : data.kind === "route"
        ? "text-primary"
        : "text-foreground";

  return (
    <div className="w-52 rounded-[2px] border bg-card p-3">
      <Handle type="target" position={Position.Left} />
      <span className="text-xs font-semibold text-muted-foreground">{nodeKindLabel(data.kind)}</span>
      <b className={`mt-1 block truncate text-xs ${tone}`}>{data.label}</b>
      <span className="data mt-1 block truncate text-xs text-muted-foreground">{data.meta}</span>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { attack: AttackNode };

export function AttackPathGraph({
  attackPaths,
  dependencies,
}: {
  attackPaths: AttackPath[];
  dependencies: Dependency[];
}) {
  const [filters, setFilters] = useState<Filters>({
    critical: false,
    reachable: false,
    exposed: false,
    direct: false,
    transitive: false,
    fix: false,
  });
  const [mode, setMode] = useState<AttackPathOrder>("highest");
  const [selectedKey, setSelectedKey] = useState("");
  const [nodeInfo, setNodeInfo] = useState<LedgerNodeData | null>(null);

  const eligible = useMemo(() => {
    const candidates = resolveAttackPathCandidates(attackPaths, dependencies).filter(({ path, dependency }) =>
      (!filters.critical || path.severity === "critical") &&
      (!filters.reachable || path.reachability === "reachable") &&
      (!filters.exposed || path.internetExposed) &&
      (!filters.direct || dependency.direct) &&
      (!filters.transitive || !dependency.direct) &&
      (!filters.fix || dependency.recommendation === "upgrade"),
    );
    return orderAttackPathCandidates(candidates, mode);
  }, [attackPaths, dependencies, filters, mode]);

  const selected = eligible.find((candidate) => candidate.path.id === selectedKey) ?? eligible[0];
  const graph = useMemo(() => buildGraph(selected), [selected]);

  function toggle(key: keyof Filters) {
    setFilters((value) => ({ ...value, [key]: !value[key] }));
    setNodeInfo(null);
  }

  return (
    <section className="surface surface-outline" data-ui="attack-path">
      <div className="flex flex-col gap-4 border-b p-5 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Crosshair className="text-primary" size={17} />
            <h2 className="font-bold">Security attack-path explorer</h2>
          </div>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-muted-foreground">
            Persisted CVE-specific evidence from this scan. Paths are static estimates, not proof that vulnerable code executes.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <select
            aria-label="Path ordering"
            value={mode}
            onChange={(event) => setMode(event.target.value as AttackPathOrder)}
            className="h-9 rounded-sm border bg-background px-3 text-xs"
          >
            <option value="highest">Highest propagated risk</option>
            <option value="shortest">Shortest persisted path</option>
          </select>
          <select
            aria-label="Selected CVE-specific attack path"
            value={selected?.path.id ?? ""}
            onChange={(event) => {
              setSelectedKey(event.target.value);
              setNodeInfo(null);
            }}
            className="h-9 max-w-80 rounded-sm border bg-background px-3 text-xs"
          >
            {eligible.map((candidate) => (
              <option key={candidate.path.id} value={candidate.path.id}>
                {candidate.path.findingId} · {candidate.dependency.name}@{candidate.dependency.version} · propagated {candidate.propagatedRisk}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b px-5 py-3" aria-label="Attack path filters">
        <Filter size={14} className="mr-1 text-muted-foreground" />
        {([
          ["critical", "Critical only"],
          ["reachable", "Reachable only"],
          ["exposed", "Internet-exposed"],
          ["direct", "Direct"],
          ["transitive", "Transitive"],
          ["fix", "Fix available"],
        ] as Array<[keyof Filters, string]>).map(([key, label]) => (
          <button
            type="button"
            key={key}
            aria-pressed={filters[key]}
            onClick={() => toggle(key)}
            className={`rounded-[2px] px-3 py-1.5 text-xs ring-1 ${
              filters[key]
                ? "bg-primary text-primary-foreground ring-primary"
                : "text-muted-foreground ring-border hover:text-foreground"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {selected ? (
        <div className="grid min-h-[520px] xl:grid-cols-[minmax(0,1fr)_340px]">
          <div className="min-w-0 border-b xl:border-b-0 xl:border-r">
            <div className="h-[440px] bg-background" data-ui="dependency-graph">
              <ReactFlow
                nodes={graph.nodes}
                edges={graph.edges}
                nodeTypes={nodeTypes}
                fitView
                minZoom={0.25}
                maxZoom={1.4}
                onNodeClick={(_, node) => setNodeInfo(node.data as LedgerNodeData)}
              >
                <Background color="var(--border)" gap={30} size={1} />
                <Controls showInteractive={false} />
              </ReactFlow>
            </div>
            <details className="border-t px-5 py-4 text-xs">
              <summary className="cursor-pointer font-semibold text-muted-foreground">Accessible path transcript</summary>
              <p className="mt-3 leading-5 text-muted-foreground">
                {selected.path.findingId} · {selected.path.evidenceKind} · {selected.path.confidence}% evidence confidence
              </p>
              <ol className="mt-3 space-y-2">
                {graph.nodes.map((node, index) => (
                  <li key={node.id} className="data text-muted-foreground">
                    {index + 1}. {String((node.data as LedgerNodeData).label)} — {(node.data as LedgerNodeData).meta}
                  </li>
                ))}
              </ol>
            </details>
          </div>
          <aside className="p-5">
            {nodeInfo ? <NodePanel data={nodeInfo} /> : <PathPanel candidate={selected} />}
          </aside>
        </div>
      ) : (
        <div className="grid min-h-72 place-items-center p-8 text-center">
          <div>
            <ShieldAlert className="mx-auto text-muted-foreground" />
            <h3 className="mt-3 font-semibold">No persisted path matches these filters</h3>
            <p className="mt-2 max-w-md text-xs leading-5 text-muted-foreground">
              Clear one or more filters. If this is an older scan, run a new project-folder scan to persist CVE-specific path evidence.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

function buildGraph(candidate?: AttackPathCandidate) {
  if (!candidate) {
    return { nodes: [] as Node<LedgerNodeData>[], edges: [] as Edge[] };
  }

  const { dependency, finding, path } = candidate;
  const findingLabel = path.cveAlias ?? path.findingId;
  const labels = path.nodes.some((node) => node.trim().toUpperCase() === findingLabel.toUpperCase())
    ? [...path.nodes]
    : [...path.nodes, findingLabel];
  const nodes: Node<LedgerNodeData>[] = labels.map((label, index) => {
    const kind = classifyNode(label, index, labels.length, dependency, findingLabel);
    const risk = kind === "dependency" || kind === "cve" ? dependency.risk : undefined;
    return {
      id: `attack-${index}`,
      type: "attack",
      position: { x: index * 260, y: 115 + (index % 2 ? 36 : 0) },
      data: {
        label,
        kind,
        meta: metaFor(kind, candidate, finding),
        risk,
        riskLabel: risk === undefined ? undefined : "Base dependency risk",
        evidence: `${path.display}. ${path.explanation}`,
      },
    };
  });
  const edges: Edge[] = nodes.slice(1).map((_, index) => ({
    id: `attack-edge-${index}`,
    source: nodes[index].id,
    target: nodes[index + 1].id,
    markerEnd: { type: MarkerType.ArrowClosed, color: "var(--primary)" },
    style: { stroke: "var(--primary)", strokeWidth: 1.75 },
  }));
  return { nodes, edges };
}

function PathPanel({ candidate }: { candidate: AttackPathCandidate }) {
  const { dependency, finding, path, propagatedRisk } = candidate;
  const propagation = dependency.propagation;
  return (
    <div>
      <span className="text-xs font-semibold text-primary">Selected persisted evidence</span>
      <h3 className="data mt-2 break-words text-lg font-bold">{path.findingId}</h3>
      <p className="mt-1 text-sm font-semibold">{dependency.name}@{dependency.version}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <SeverityBadge severity={path.severity} />
        <Badge tone={dependency.direct ? "direct" : "neutral"}>{dependency.direct ? "Direct" : "Transitive"}</Badge>
        <Badge>{path.reachability.replaceAll("-", " ")}</Badge>
      </div>
      <dl className="mt-6 space-y-4" data-ui="propagation-evidence">
        <PanelDatum label="Base dependency risk" value={`${dependency.risk}/100`} />
        <PanelDatum label="Own contextual priority" value={`${propagation?.ownRisk ?? dependency.contextual?.finalPriority ?? dependency.risk}/100`} />
        <PanelDatum label="Inherited graph risk" value={propagation ? `${propagation.inheritedRisk}/100` : "Not assessed"} />
        <PanelDatum label="Propagated contextual risk" value={`${propagatedRisk}/100`} />
        <PanelDatum label="Finding CVSS" value={finding?.cvssAvailable === false || !finding ? "Unavailable" : finding.cvss.toFixed(1)} />
        <PanelDatum label="Path confidence" value={`${path.confidence}%`} />
        <PanelDatum label="Persisted nodes" value={String(path.nodes.length)} />
        <PanelDatum label="Fix" value={dependency.recommendation === "upgrade" ? dependency.latest : "No complete target"} />
      </dl>
      <p className="mt-6 text-xs leading-5 text-muted-foreground">{path.explanation}</p>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">
        Propagated risk is a derived DepShield heuristic. It does not replace the base dependency risk or prove exploitability.
      </p>
    </div>
  );
}

function NodePanel({ data }: { data: LedgerNodeData }) {
  return (
    <div>
      <div className="flex items-center gap-2 text-primary">
        <Info size={16} />
        <span className="text-xs font-semibold">Node evidence</span>
      </div>
      <h3 className="mt-3 break-words font-bold">{data.label}</h3>
      <p className="data mt-2 text-xs text-muted-foreground">{nodeKindLabel(data.kind)} · {data.meta}</p>
      {data.risk !== undefined ? (
        <div className="mt-5">
          <span className="text-xs text-muted-foreground">{data.riskLabel}</span>
          <p className="data mt-1 text-3xl font-bold text-warning">
            {data.risk}<span className="text-sm text-muted-foreground">/100</span>
          </p>
        </div>
      ) : null}
      <p className="mt-5 break-words text-xs leading-5 text-muted-foreground">{data.evidence}</p>
    </div>
  );
}

function PanelDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 border-b pb-3 last:border-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="data text-right text-xs font-semibold">{value}</dd>
    </div>
  );
}

function classifyNode(
  label: string,
  index: number,
  length: number,
  dependency: Dependency,
  findingLabel: string,
) {
  if (label.trim().toUpperCase() === findingLabel.trim().toUpperCase() || /^(CVE-|GHSA-)/i.test(label)) return "cve";
  if (/^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s\//.test(label)) return "route";
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(label)) return "module";
  if (label === `${dependency.name}@${dependency.version}` || (label.includes("@") && index < length - 1)) return "dependency";
  return index === 0 ? "application" : "dependency";
}

function nodeKindLabel(kind: string) {
  return ({
    route: "Route hint",
    module: "Application module",
    dependency: "Dependency",
    cve: "Vulnerability",
    application: "Application",
  } as Record<string, string>)[kind] ?? "Evidence";
}

function metaFor(kind: string, candidate: AttackPathCandidate, finding: Vulnerability | null) {
  if (kind === "cve") {
    return finding?.cvssAvailable === false || !finding
      ? `${candidate.path.severity} · CVSS unavailable`
      : `${candidate.path.severity} · CVSS ${finding.cvss.toFixed(1)}`;
  }
  if (kind === "dependency") {
    return `base ${candidate.dependency.risk} · propagated ${candidate.propagatedRisk}`;
  }
  if (kind === "route") {
    return candidate.path.internetExposed ? "Internet-exposed route hint" : "Route hint";
  }
  return `${candidate.path.evidenceKind} evidence`;
}
