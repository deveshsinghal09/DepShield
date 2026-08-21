import { NextResponse } from "next/server";

export const runtime="nodejs";
export const dynamic="force-dynamic";

const demoUrl="http://127.0.0.1:4100/demo/prototype-pollution";

export async function POST(){
  if(process.env.NODE_ENV==="production"&&process.env.DEPSHIELD_ENABLE_ATTACK_REPLAY!=="true")return NextResponse.json({error:{code:"REPLAY_DISABLED",message:"Attack Replay is disabled in production. Run DepShield and vulnerable-demo locally."}},{status:403});
  try{
    const response=await fetch(demoUrl,{method:"POST",headers:{accept:"application/json"},cache:"no-store",signal:AbortSignal.timeout(5000)});
    const result=await response.json() as Record<string,unknown>;
    if(!response.ok)throw new Error(typeof result.error==="string"?result.error:`Demo returned HTTP ${response.status}`);
    return NextResponse.json({data:result,meta:{target:"fixed-localhost-fixture",route:"POST /demo/prototype-pollution"}});
  }catch(error){
    const message=error instanceof Error?error.message:"The local demo did not respond.";
    return NextResponse.json({error:{code:"DEMO_UNAVAILABLE",message:`Could not reach the local fixture at 127.0.0.1:4100. Start it with npm run demo:start. ${message}`}},{status:503});
  }
}
