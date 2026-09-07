import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { RawAdvisory, SourceStatus } from "@/lib/types";
import { severityFromScore } from "./cvss";

type Via={source?:number;name?:string;dependency?:string;title?:string;url?:string;severity?:string;range?:string;cvss?:{score?:number;vectorString?:string}};
type AuditFinding={name?:string;severity?:string;via?:(Via|string)[];range?:string;fixAvailable?:boolean|{name?:string;version?:string;isSemVerMajor?:boolean}};
type AuditBody={vulnerabilities?:Record<string,AuditFinding>;error?:{message?:string;summary?:string;detail?:string}};
export type AuditResult={findings:Map<string,RawAdvisory[]>;status:SourceStatus;warning?:string};

export async function runNpmAudit(packageText:string,lockText:string):Promise<AuditResult>{
  const findings=new Map<string,RawAdvisory[]>(),directory=await mkdtemp(path.join(tmpdir(),"depshield-audit-")),retrievedAt=new Date().toISOString();
  try{
    await Promise.all([writeFile(path.join(directory,"package.json"),packageText),writeFile(path.join(directory,"package-lock.json"),lockText)]);
    let stdout="",stderr="";
    try{
      const command=process.platform==="win32"?(process.env.ComSpec??"C:\\Windows\\System32\\cmd.exe"):"npm";
      const args=process.platform==="win32"?["/d","/s","/c","npm audit --json"]:["audit","--json"];
      const result=await executeAudit(command,args,directory);
      stdout=result.stdout;stderr=result.stderr;
    }catch(error){
      const value=error as{stdout?:string;stderr?:string;code?:number|string};stdout=value.stdout??"";stderr=value.stderr??"";
      if(!stdout.trim())return failed(`npm audit failed${value.code?` (${value.code})`:""}: ${stderr.trim()||"no JSON output"}`);
    }
    let body:AuditBody;
    try{body=JSON.parse(stdout)}catch{return failed(`npm audit returned invalid JSON${stderr?`: ${stderr.trim()}`:"."}`)}
    if(body.error){const detail=body.error.message||body.error.summary||body.error.detail||stderr.trim()||"registry audit endpoint returned an error";return failed(`npm audit failed: ${detail}`)}
    if(!body.vulnerabilities)return failed("npm audit returned JSON without a vulnerabilities result.");
    for(const[name,item]of Object.entries(body.vulnerabilities??{})){
      // npm can recommend upgrading a parent package. That version is not a
      // exact fixed version reported for the vulnerable child, so only retain an
      // exact same-package fix here.
      const fix=typeof item.fixAvailable==="object"&&item.fixAvailable.name===name?item.fixAvailable.version??null:null;
      const advisories:RawAdvisory[]=(item.via??[]).filter((v):v is Via=>typeof v!=="string").map(v=>{
        const parsed=typeof v.cvss?.score==="number"&&v.cvss.score>0?v.cvss.score:null,id=extractId(v.url)??(v.source?`npm-${v.source}`:`npm-${name}-${v.title??"advisory"}`),cve=id.startsWith("CVE-")?id:null;
        return{id,aliases:[id],cveAlias:cve,cvss:parsed??0,cvssAvailable:parsed!==null,cvssVector:v.cvss?.vectorString??null,severity:severityFromScore(parsed,v.severity??item.severity),summary:v.title??`npm audit advisory for ${name}`,vulnerableRange:v.range??item.range??null,fixedVersion:fix,references:v.url?[v.url]:[],source:"npm" as const,retrievedAt};
      });
      findings.set(name,advisories);
    }
    return{findings,status:{source:"npm-audit",status:"ok",message:null,retrievedAt,confidence:85}};
  }finally{await rm(directory,{recursive:true,force:true})}
}

function executeAudit(command:string,args:string[],cwd:string){
  return new Promise<{stdout:string;stderr:string}>((resolve,reject)=>{
    execFile(command,args,{cwd,maxBuffer:16_000_000,timeout:120_000,windowsHide:true},(error,stdout,stderr)=>{
      const output={stdout:String(stdout??""),stderr:String(stderr??"")};
      if(error){
        Object.assign(error,output);
        reject(error);
        return;
      }
      resolve(output);
    });
  });
}

function failed(message:string):AuditResult{return{findings:new Map(),status:{source:"npm-audit",status:"failed",message,retrievedAt:new Date().toISOString(),confidence:0},warning:message}}
function extractId(url?:string){if(!url)return null;const match=url.match(/(CVE-\d{4}-\d+|GHSA-[\w-]+)/i);return match?.[1]?.toUpperCase()??null}
