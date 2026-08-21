import type{Dependency,Scan,Severity}from"./types";
export const severityOrder:Severity[]=["critical","high","medium","low","unknown"];
export function severityCounts(scan:Scan){const counts:Record<Severity,number>={critical:0,high:0,medium:0,low:0,unknown:0};for(const item of scan.items)for(const vulnerability of item.vulnerabilities)counts[vulnerability.severity]++;return counts}
export function highCount(scan:Scan){const counts=severityCounts(scan);return counts.critical+counts.high}
export function fixableCount(scan:Scan){return scan.items.reduce((sum,item)=>sum+item.vulnerabilities.filter(v=>Boolean(v.fixedVersion)).length,0)}
export function cveCount(scan:Scan){return scan.items.reduce((sum,item)=>sum+item.vulnerabilities.length,0)}
export function topRisk(scan:Scan,limit=8){return scan.items.filter(item=>item.risk>0).toSorted((a,b)=>b.risk-a.risk).slice(0,limit)}
export function highestCvss(item:Dependency){return Math.max(0,...item.vulnerabilities.map(v=>v.cvss))}
export function compareScans(before:Scan,after:Scan){const a=severityCounts(before),b=severityCounts(after),beforeCves=new Set(before.items.flatMap(i=>i.vulnerabilities.map(v=>v.cveAlias??v.id))),afterCves=new Set(after.items.flatMap(i=>i.vulnerabilities.map(v=>v.cveAlias??v.id))),removed=[...beforeCves].filter(id=>!afterCves.has(id)).length,beforeVersions=new Map(before.items.map(i=>[`${i.name}@${i.path}`,i.version])),upgraded=after.items.filter(i=>beforeVersions.has(`${i.name}@${i.path}`)&&beforeVersions.get(`${i.name}@${i.path}`)!==i.version).length,beforeRisk=100-before.score,afterRisk=100-after.score,riskReduction=beforeRisk===0?(afterRisk===0?0:-100):Math.round(((beforeRisk-afterRisk)/beforeRisk)*100);return{before:a,after:b,removed,upgraded,riskReduction}}
