import { randomUUID } from "node:crypto";
import type { Dependency, Scan, ScanWarning } from "../lib/types";
import { dependencyRisk, grade, projectScore } from "../lib/risk";
import { mergeAdvisories, compareVersions } from "./advisory-merge";
import { extractDependencyGraph, parseLockfile, parseManifest } from "./dependency-tree";
import { runNpmAudit } from "./npm-audit";
import { queryOsv } from "./osv-client";

export type ScannerDependencies = { audit?:typeof runNpmAudit; osv?:typeof queryOsv };

export async function scanProject(packageText:string,lockText:string|undefined,services:ScannerDependencies={}):Promise<Scan>{
  const started=Date.now(),manifest=parseManifest(packageText),lock=parseLockfile(lockText),installed=extractDependencyGraph(manifest,lock);
  const [audit,osv]=await Promise.all([(services.audit??runNpmAudit)(packageText,lockText!),(services.osv??queryOsv)(installed)]);
  const warnings:ScanWarning[]=[];
  if(audit.warning)warnings.push({code:"NPM_AUDIT_FAILED",message:audit.warning,recoverable:true});
  if(osv.warning)warnings.push({code:"OSV_API_FAILED",message:osv.warning,recoverable:true});
  const items:Dependency[]=installed.map(dep=>{
    const advisories=mergeAdvisories([...(audit.findings.get(dep.name)??[]),...(osv.findings.get(`${dep.name}@${dep.version}`)??[])]);
    if(advisories.some(v=>v.cvssAvailable===false))warnings.push({code:"MISSING_CVSS",message:`${dep.name}@${dep.version} has an advisory without a CVSS score; severity metadata was retained.`,recoverable:true});
    const highest=Math.max(0,...advisories.map(v=>v.cvss)),fixes=advisories.map(v=>v.fixedVersion).filter((v):v is string=>Boolean(v)).sort(compareVersions),allFixed=advisories.length>0&&advisories.every(v=>Boolean(v.fixedVersion)),someFixed=fixes.length>0,recommended=allFixed?fixes.at(-1)!:dep.version;
    const recommendation:Dependency["recommendation"]=advisories.length===0?"none":allFixed?"upgrade":someFixed?"partial-fix":"no-fix";
    return{name:dep.name,version:dep.version,direct:dep.direct,path:dep.paths[0]?.display??`${manifest.name??"Application"} → ${dep.name}@${dep.version}`,paths:dep.paths,license:dep.license,vulnerabilities:advisories,risk:dependencyRisk(highest,dep.direct,allFixed,advisories.length),latest:recommended,recommendation};
  }).sort((a,b)=>b.risk-a.risk||a.name.localeCompare(b.name));
  const score=projectScore(items),uniqueWarnings=[...new Map(warnings.map(w=>[`${w.code}:${w.message}`,w])).values()];
  return{id:randomUUID(),createdAt:new Date().toISOString(),project:manifest.name??"uploaded-project",branch:"uploaded",score,grade:grade(score),dependencies:items.length,vulnerable:items.filter(i=>i.vulnerabilities.length>0).length,critical:items.filter(i=>i.vulnerabilities.some(v=>v.severity==="critical")).length,duration:Math.max(1,Math.round((Date.now()-started)/1000)),items,dependencyTree:items.flatMap(item=>item.paths??[]),sourceStatus:[audit.status,osv.status],warnings:uniqueWarnings};
}
