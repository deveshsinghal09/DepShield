// THESIS: dependency evidence in the approved compact analytics layout.
// OWN-WORLD: charcoal clay panels, recessed controls, crimson actions.
// STORY: inspect posture, understand findings, choose the next upgrade.
// FIRST VIEWPORT: four metrics, wide history chart, severity donut, package table.
// FORM: user-approved preview two; real 3D wirefield lives in the sidebar.
import Link from 'next/link';
import {Package,ShieldCheck,TriangleAlert,Wrench} from 'lucide-react';
import type {Scan} from '@/lib/types';
import {severityCounts,topRisk} from '@/lib/scan-selectors';
import {DependencyTable} from '@/components/dependency-table';
import {RiskChart} from '@/components/risk-chart';
import {SeverityChart} from '@/components/severity-chart';
import {SourceCoverage} from '@/components/source-coverage';
import {CriticalAction} from '@/components/critical-action';
import {RemediationSummary} from '@/components/remediation-summary';
import {RegressionAlerts} from '@/components/regression-alerts';

export function DashboardOverview({scan,scans}:{scan:Scan;scans:Scan[]}){
  const counts=severityCounts(scan);
  const findings=Object.values(counts).reduce((sum,value)=>sum+value,0);
  const direct=scan.items.filter(item=>item.direct).length;
  const fixable=scan.items.filter(item=>item.vulnerabilities.length>0&&item.vulnerabilities.every(v=>Boolean(v.fixedVersion))).length;
  const history=scans.filter(item=>item.project===scan.project&&new Date(item.createdAt)<=new Date(scan.createdAt));
  const previous=history.find(item=>item.id!==scan.id);
  return <div className="dashboard-overview" data-ui="dashboard">
    <div className="dashboard-context"><div><span>Project</span><strong>{scan.project}</strong></div><p>Scanned <time dateTime={scan.createdAt}>{new Date(scan.createdAt).toLocaleString('en-GB',{timeZone:'UTC'})} UTC</time></p></div>
    <dl className="dashboard-metrics" data-ui="metric-strip">
      <div className="clay-panel dashboard-metric" data-ui="security-score"><dt><ShieldCheck size={19}/>Security score</dt><dd><strong>{scan.score}<small>/100</small></strong><span className="grade-chip">Grade {scan.grade}</span></dd><p>{previous?`${scan.score-previous.score>=0?'+':''}${scan.score-previous.score} points vs previous scan`:'First scan for this project'}</p></div>
      <div className="clay-panel dashboard-metric"><dt><Package size={19}/>Dependencies</dt><dd><strong>{scan.dependencies}</strong></dd><p>{direct} direct <span>/</span> {Math.max(0,scan.dependencies-direct)} transitive</p></div>
      <div className="clay-panel dashboard-metric"><dt><TriangleAlert size={19}/>Open findings</dt><dd><strong>{findings}</strong></dd><p><span className="critical-copy">{counts.critical} critical</span> <span>/</span> {counts.high} high</p></div>
      <div className="clay-panel dashboard-metric"><dt><Wrench size={19}/>Fixable packages</dt><dd><strong>{fixable}</strong></dd><p>Of {scan.vulnerable} vulnerable packages</p></div>
    </dl>
    <div className="dashboard-charts">
      <section className="clay-panel chart-panel"><div className="panel-heading"><div><h2>Security score history</h2><p>Saved scans for this project · higher is better</p></div></div><RiskChart scans={history}/>{history.length===1&&<p className="chart-note">One saved scan. Scan again after remediation to measure progress.</p>}</section>
      <section className="clay-panel chart-panel"><div className="panel-heading"><div><h2>Findings by severity</h2><p>Advisories across installed packages</p></div></div><SeverityChart scan={scan}/></section>
    </div>
    <section className="clay-panel dashboard-table"><div className="panel-heading"><div><h2>Priority dependencies <span className="count-chip">{scan.vulnerable}</span></h2><p>Highest-risk packages in this scan</p></div><Link href={`/dependencies?scan=${encodeURIComponent(scan.id)}`}>View all dependencies →</Link></div><DependencyTable items={topRisk(scan,scan.items.length)} compact showFilters scanId={scan.id} emptyMessage="No risky dependencies found in this scan."/></section>
    <SourceCoverage scan={scan}/>
    <div className="dashboard-actions"><CriticalAction scan={scan}/><RemediationSummary scan={scan}/></div>
    <RegressionAlerts scan={scan} previous={previous}/>
  </div>;
}
