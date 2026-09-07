"use client";

import { ShieldCheck } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { Scan } from "@/lib/types";
import { severityCounts, severityOrder } from "@/lib/scan-selectors";
import { scanIsIncomplete } from "./source-coverage";

const colors = {
  critical: "#ff3b3b",
  high: "#ff5b4f",
  medium: "#ffb020",
  low: "#b8cf54",
  unknown: "#73736e",
};

export function SeverityChart({ scan }: { scan: Scan }) {
  const counts = severityCounts(scan);
  const data = severityOrder
    .map((name) => ({ name, value: counts[name], color: colors[name] }))
    .filter((item) => item.value > 0);
  const total = data.reduce((sum, item) => sum + item.value, 0);
  const incomplete = scanIsIncomplete(scan);

  if (total === 0) {
    return (
      <div className="grid min-h-48 place-items-center text-center" data-ui="severity-chart">
        <div>
          <span className={`mx-auto grid size-11 place-items-center border ${incomplete ? "border-warning/40 text-warning" : "border-safe/40 text-safe"}`}><ShieldCheck size={20} /></span>
          <b className="mt-3 block text-sm">{incomplete ? "No findings from completed sources" : "No known vulnerabilities"}</b>
          <span className="mt-1 block text-xs text-muted-foreground">{incomplete ? "Review scan coverage before accepting this result." : "The latest scan returned zero findings."}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="grid items-center gap-2 sm:grid-cols-[1fr_150px]" data-ui="severity-chart">
      <div className="relative h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={78} paddingAngle={1} stroke="#0a0a0a" strokeWidth={2}>
              {data.map((item) => <Cell key={item.name} fill={item.color} />)}
            </Pie>
            <Tooltip contentStyle={{ background: "#141414", border: "1px solid #343432", borderRadius: 2, color: "#f5f5f0" }} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <span><b className="data block text-2xl">{total}</b><small className="text-muted-foreground">findings</small></span>
        </div>
      </div>
      <div className="space-y-2">
        {data.map((item) => (
          <div key={item.name} className="flex items-center justify-between gap-4 border-b border-border/70 pb-2 text-xs last:border-0">
            <span className="flex items-center gap-2 capitalize text-muted-foreground"><i className="size-2" style={{ background: item.color }} />{item.name}</span>
            <b className="data">{item.value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}
