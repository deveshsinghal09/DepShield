"use client";
import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Check, LoaderCircle, ScanLine, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";

type State={kind:"idle"|"loading"|"done"|"error";message?:string};

export function ScanButton(){
  const input=useRef<HTMLInputElement>(null),router=useRouter(),[state,setState]=useState<State>({kind:"idle"});
  async function scan(files:FileList|null){if(!files?.length)return;const values=Array.from(files),manifest=values.find(f=>f.name==="package.json"),lock=values.find(f=>f.name==="package-lock.json");if(!manifest||!lock){setState({kind:"error",message:"Select both package.json and package-lock.json."});return}setState({kind:"loading"});try{const response=await fetch("/api/scans",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({packageJson:await manifest.text(),packageLock:await lock.text()})}),body=await response.json() as{error?:{message?:string}};if(!response.ok)throw new Error(body.error?.message??"Scan failed.");setState({kind:"done",message:"Scan saved"});router.refresh();setTimeout(()=>setState({kind:"idle"}),2500)}catch(error){setState({kind:"error",message:error instanceof Error?error.message:"Scan failed."})}}
  function chooseFiles(){if(!input.current)return;input.current.value="";input.current.click()}
  const loading=state.kind==="loading",label=loading?"Scanning project":state.kind==="done"?"Scan complete":state.kind==="error"?state.message??"Scan failed":"Scan Project";
  return <div className="relative" data-ui="scan-button"><input ref={input} className="sr-only" type="file" accept="application/json,.json" multiple onChange={event=>scan(event.target.files)} aria-label="Choose package.json and package-lock.json"/><Button className="scan-pulse min-w-32" aria-label={label} disabled={loading} onClick={chooseFiles}>{loading?<LoaderCircle className="animate-spin" size={16}/>:state.kind==="done"?<Check size={16}/>:state.kind==="error"?<TriangleAlert size={16}/>:<ScanLine size={16}/>} {loading?"Scanning…":state.kind==="done"?"Scan saved":"Scan Project"}</Button>{state.kind==="error"?<div role="alert" className="absolute right-0 top-12 z-50 w-72 rounded-sm border border-destructive/30 bg-card p-3 text-xs text-destructive shadow-lg">{state.message}</div>:null}</div>
}
