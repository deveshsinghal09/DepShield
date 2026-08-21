import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { RawAdvisory, SourceStatus } from "@/lib/types";
import { severityFallback, severityFromScore } from "./cvss";

const exec=promisify(execFile);
type Via={source?:number;name?:string;dependency?:string;title?:string;url?:string;severity?:string;range?:string;cvss?:{score?:number;vectorString?:string}};
type AuditFinding={name?:string;severity?:string;via?:(Via|string)[];range?:string;fixAvailable?:boolean|{name?:string;version?:string;isSemVerMajor?:boolean}};
export type AuditResult={findings:Map<string,RawAdvisory[]>;status:SourceStatus;warning?:string};

export async function runNpmAudit(packageText:string,lockText:string):Promise<AuditResult>{
  const findings=new Map<string,RawAdvisory[]>(),directory=await mkdtemp(path.join(tmpdir(),"depshield-audit-"));
  try{
    await Promise.all([writeFile(path.join(directory,"package.json"),packageText),writeFile(path.join(directory,"package-lock.json"),lockText)]);
    let stdout="",stderr="";
    try{
      const command=process.platform==="win32"?(process.env.ComSpec??"C:\\Windows\\System32\\cmd.exe"):"npm";
      const args=process.platform==="win32"?["/d","/s","/c","npm audit --json --omit=dev"]:["audit","--json","--omit=dev"];
      const result=await exec(command,args,{cwd:directory,maxBuffer:16_000_000,timeout:120_000,windowsHide:true});
      stdout=result.stdout;stderr=result.stderr;
    }catch(error){
      const value=error as{stdout?:string;stderr?:string;code?:number|string};stdout=value.stdout??"";stderr=value.stderr??"";
      if(!stdout.trim())return failed(`npm audit failed${value.code?` (${value.code})`:""}: ${stderr.trim()||"no JSON output"}`);
    }
    let body:{vulnerabilities?:Record<string,AuditFinding>};
    try{body=JSON.parse(stdout)}catch{return failed(`npm audit returned invalid JSON${stderr?`: ${stderr.trim()}`:"."}`)}
    for(const[name,item]of Object.entries(body.vulnerabilities??{})){
      const fix=typeof item.fixAvailable==="object"?item.fixAvailable.version??null:null;
      const advisories:RawAdvisory[]=(item.via??[]).filter((v):v is Via=>typeof v!=="string").map(v=>{
        const parsed=typeof v.cvss?.score==="number"&&v.cvss.score>0?v.cvss.score:severityFallback(v.severity??item.severity),id=extractId(v.url)??(v.source?`npm-${v.source}`:`npm-${name}-${v.title??"advisory"}`),cve=id.startsWith("CVE-")?id:null;
        return{id,aliases:[id],cveAlias:cve,cvss:parsed??0,cvssAvailable:parsed!==null,cvssVector:v.cvss?.vectorString??null,severity:severityFromScore(parsed,v.severity??item.severity),summary:v.title??`npm audit advisory for ${name}`,vulnerableRange:v.range??item.range??null,fixedVersion:fix,references:v.url?[v.url]:[],source:"npm" as const};
      });
      findings.set(name,advisories);
    }
    return{findings,status:{source:"npm-audit",status:"ok",message:null}};
  }finally{await rm(directory,{recursive:true,force:true})}
}

function failed(message:string):AuditResult{return{findings:new Map(),status:{source:"npm-audit",status:"failed",message},warning:message}}
function extractId(url?:string){if(!url)return null;const match=url.match(/(CVE-\d{4}-\d+|GHSA-[\w-]+)/i);return match?.[1]?.toUpperCase()??null}
