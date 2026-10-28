import { SecurityButton } from './primitives';

export function SecurityHero({onSecure}:{onSecure:()=>void}) {
  return <section className="hero" aria-labelledby="headline" data-ui="landing-hero">
    <h1 id="headline"><span className="ln"><span>Dependency risk.</span></span><span className="ln"><span>Under your control.</span></span></h1>
    <p className="sub">Scan npm dependencies. Investigate CVEs.<br/>Prioritize upgrades and compare results.</p>
    <SecurityButton className="btn-cta" onClick={onSecure} data-ui="scan-button" />
  </section>;
}
export type LandingSummary = {scans:number;score:number|null;dependencies:number|null};
export function SecurityStats({summary}:{summary:LandingSummary}) {
  const stats=[{value:summary.scans,label:'Saved scans'},{value:summary.score===null?'—':`${summary.score}/100`,label:'Latest score'},{value:summary.dependencies??'—',label:'Dependencies'}];
  return <section className="stats" data-ui="scan-summary" aria-label="Saved scans and latest scan results">
    {stats.map((stat,i)=><div key={stat.label} className={`stat s${i+1}`}><span className="num">{stat.value}</span><span className="lab">{stat.label}</span></div>)}
    <i className="rule r1" aria-hidden="true"/><i className="rule r2" aria-hidden="true"/>
  </section>;
}
