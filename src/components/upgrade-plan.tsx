"use client";
import Link from"next/link";
import{useState}from"react";
import{ArrowRight,CheckCircle2,ListChecks}from"lucide-react";
import type{Scan}from"@/lib/types";
import{generateUpgradePlan}from"@/lib/remediation";
import{Button}from"./ui/button";
import{Badge}from"./ui/badge";

export function UpgradePlan({scan}:{scan:Scan}){
  const[generated,setGenerated]=useState(false),plan=generated?generateUpgradePlan(scan.items):[];
  return <section className="surface surface-outline" data-ui="upgrade-plan"><div className="flex flex-col justify-between gap-4 border-b p-5 sm:flex-row sm:items-center"><div><h2 className="font-bold">Upgrade plan</h2><p className="mt-1 text-xs text-muted-foreground">Risk dominates priority; easier safe changes break ties.</p></div><Button variant="outline" onClick={()=>setGenerated(true)} disabled={generated}><ListChecks size={15}/>{generated?"Plan generated":"Generate Upgrade Plan"}</Button></div>{generated?(plan.length?<ol>{plan.slice(0,8).map((item,index)=><li key={`${item.dependency.name}-${item.dependency.path}`} className="grid gap-3 border-b px-5 py-4 last:border-0 sm:grid-cols-[2rem_1fr_auto] sm:items-center"><span className="data text-xs text-muted-foreground">{String(index+1).padStart(2,"0")}</span><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Link className="font-semibold hover:text-primary" href={`/dependencies/${encodeURIComponent(item.dependency.name)}?scan=${scan.id}&version=${item.dependency.version}&path=${encodeURIComponent(item.dependency.path)}`}>{item.dependency.name}</Link><Badge tone={item.label==="No Fix Available"?"critical":item.label==="Major Upgrade"?"medium":"neutral"}>{item.label}</Badge></div><p className="data mt-1 truncate text-xs text-muted-foreground">{item.dependency.version}{item.targetVersion?` → ${item.targetVersion}`:" · isolate, replace, or remove"}</p></div><span className={`data text-sm font-bold ${item.dependency.risk>=80?"text-destructive":"text-warning"}`}>risk {item.dependency.risk}</span></li>)}</ol>:<div className="flex items-center gap-3 p-5 text-sm text-muted-foreground"><CheckCircle2 className="text-safe" size={18}/>No vulnerable dependencies require a plan.</div>):<div className="flex items-center justify-between gap-4 p-5 text-sm text-muted-foreground"><p>Generate a deterministic, interview-friendly remediation queue from this scan.</p><ArrowRight className="shrink-0 text-primary" size={17}/></div>}</section>;
}
