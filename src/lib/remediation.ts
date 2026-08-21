import type { Dependency, RemediationLabel, UpgradePlanItem } from "./types";

function numbers(version:string){return version.replace(/^[^0-9]*/,"").split(/[.-]/).slice(0,3).map(value=>Number(value)||0)}

export function remediationLabel(dependency:Dependency):RemediationLabel|null{
  if(!dependency.vulnerabilities.length)return null;
  if(dependency.recommendation==="no-fix"||dependency.recommendation==="partial-fix"||dependency.latest===dependency.version)return "No Fix Available";
  if(!dependency.direct)return "Update Parent Dependency";
  const [currentMajor,currentMinor]=numbers(dependency.version),[targetMajor,targetMinor]=numbers(dependency.latest);
  if(targetMajor>currentMajor)return "Major Upgrade";
  if(targetMinor>currentMinor)return "Minor Upgrade";
  return "Safe Auto Fix";
}

const effort:Record<RemediationLabel,number>={"Safe Auto Fix":0,"Minor Upgrade":1,"Update Parent Dependency":2,"Major Upgrade":3,"No Fix Available":4};

export function generateUpgradePlan(items:Dependency[]):UpgradePlanItem[]{
  return items.flatMap(dependency=>{const label=remediationLabel(dependency);if(!label)return[];const item:UpgradePlanItem={dependency,label,targetVersion:label==="No Fix Available"?null:dependency.latest,effort:effort[label],priority:dependency.risk*10-effort[label]};return[item]}).toSorted((a,b)=>b.priority-a.priority||a.dependency.name.localeCompare(b.dependency.name));
}
