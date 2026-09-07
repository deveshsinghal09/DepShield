import Link from "next/link";
import { ArrowRight } from "lucide-react";
import type { Scan } from "@/lib/types";
import { severityCounts, fixableCount, topRisk } from "@/lib/scan-selectors";

export function HomeEvidence({ scan }: { scan: Scan | null }) {
  const counts = scan ? severityCounts(scan) : null;
  const rows = scan ? topRisk(scan, 5) : [];
  const query = scan ? `?scan=${encodeURIComponent(scan.id)}` : "";
  return <section className="home-evidence" data-ui="scan-command-center" aria-label="Latest saved scan">
    <div className="home-status"><span><i />{scan ? "SAVED SCAN" : "READY TO SCAN"}</span><span>{scan?.project ?? "Choose a Node.js project to begin"}</span><span>{scan ? `${scan.dependencies} dependencies` : "package.json + package-lock.json"}</span><Link href={scan ? `/${query}` : "/scan"}>{scan ? "Open dashboard" : "Start first scan"}<ArrowRight size={13} /></Link></div>
    <div className="home-evidence-grid">
      <article className="home-panel" data-ui="project-grade"><h2>Project grade</h2><strong className={`home-grade ${scan && ["D", "E", "F"].includes(scan.grade) ? "text-critical" : "text-primary"}`}>{scan?.grade ?? "—"}</strong><p>{scan ? (scan.score >= 80 ? "Lower dependency risk" : "Remediation recommended") : "Your grade appears after the first scan."}</p></article>
      <article className="home-panel" data-ui="security-score"><h2>Security score</h2><div className="home-score"><strong>{scan?.score ?? "—"}</strong><span>/100</span></div><div className="home-score-track" aria-hidden="true"><span style={{ width: `${scan?.score ?? 0}%` }} /></div><p>{scan ? `${fixableCount(scan)} findings have a known fix` : "A clear baseline for every upgrade."}</p></article>
      <article className="home-panel" data-ui="severity-chart"><h2>Vulnerabilities</h2><dl className="home-severities">{(["critical", "high", "medium", "low", "unknown"] as const).map((severity) => <div key={severity}><dt className={`text-${severity}`}>{severity}</dt><dd>{counts?.[severity] ?? "—"}</dd></div>)}</dl><p>{scan ? `${scan.vulnerable} affected dependencies` : "No vulnerability evidence yet."}</p></article>
      <article className="home-panel home-ledger" data-ui="risk-table"><div className="flex items-center justify-between gap-3"><h2>Dependency evidence</h2>{scan ? <Link className="text-xs text-primary" href={`/dependencies${query}`}>View all <span aria-hidden="true">↗</span></Link> : null}</div><div className="scrollbar overflow-x-auto"><table><thead><tr><th>Package</th><th>Version</th><th>Scope</th><th>Findings</th><th>Risk</th></tr></thead><tbody>{rows.map((item) => <tr key={item.path}><td><Link href={`/dependencies/${encodeURIComponent(item.name)}${query}&version=${encodeURIComponent(item.version)}&path=${encodeURIComponent(item.path)}`}>{item.name}</Link></td><td>{item.version}</td><td>{item.direct ? "Direct" : "Transitive"}</td><td>{item.vulnerabilities.length}</td><td className={item.risk >= 80 ? "text-critical" : "text-warning"}>{item.risk}</td></tr>)}</tbody></table>{!rows.length ? <div className="home-ledger-empty">{scan ? "No vulnerable dependencies found in this scan." : "Scan your manifests to see the dependencies that need attention."}<Link href="/scan">Scan project <ArrowRight size={14} /></Link></div> : null}</div></article>
    </div>
    {scan ? <footer className="home-scan-footer"><span>Last scan · {new Date(scan.createdAt).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</span><span>{scan.duration.toFixed(1)}s duration</span><Link href="/scan">Rescan project →</Link></footer> : null}
  </section>;
}
