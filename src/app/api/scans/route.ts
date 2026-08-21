import { NextResponse } from "next/server";
import { getScan, listScans, saveScan } from "@/server/db";
import { ManifestError } from "@/server/dependency-tree";
import { scanProject } from "@/server/scanner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 180;

export async function GET(request:Request){
  const id=new URL(request.url).searchParams.get("id");
  if(id){const scan=getScan(id);return scan?NextResponse.json({data:scan}):NextResponse.json({error:{code:"SCAN_NOT_FOUND",message:"The requested scan does not exist."}},{status:404})}
  return NextResponse.json({data:listScans()});
}

export async function POST(request:Request){
  try{
    const body=await request.json() as{packageJson?:unknown;packageLock?:unknown};
    if(typeof body.packageJson!=="string"||!body.packageJson.trim())return invalid("PACKAGE_JSON_REQUIRED","package.json is required.");
    if(typeof body.packageLock!=="string"||!body.packageLock.trim())return invalid("PACKAGE_LOCK_REQUIRED","package-lock.json is required. Generate it with npm install --package-lock-only before scanning.",422);
    const scan=saveScan(await scanProject(body.packageJson,body.packageLock));
    return NextResponse.json({data:scan,meta:{warnings:scan.warnings??[],sources:scan.sourceStatus??[]}},{status:201});
  }catch(error){
    if(error instanceof ManifestError)return invalid(error.code,error.message,error.code==="NO_LOCKFILE"?422:400);
    if(error instanceof SyntaxError)return invalid("INVALID_REQUEST_JSON","The request body is not valid JSON.");
    console.error("Dependency scan failed",error);
    return NextResponse.json({error:{code:"SCAN_FAILED",message:"The scan could not be completed. Verify the manifests and try again."}},{status:500});
  }
}

function invalid(code:string,message:string,status=400){return NextResponse.json({error:{code,message}},{status})}
