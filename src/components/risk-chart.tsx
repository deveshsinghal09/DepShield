"use client";

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Scan } from "@/lib/types";

export function RiskChart({ scans }: { scans: Scan[] }) {
  const data = scans.toReversed().map((scan) => ({
    date: new Date(scan.createdAt).toLocaleDateString("en", { month: "short", day: "numeric", timeZone: "UTC" }),
    score: scan.score,
  }));

  return (
    <div className="h-64 w-full" data-ui="risk-trend">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 12, right: 8, left: -24, bottom: 0 }}>
          <CartesianGrid stroke="#343432" vertical={false} />
          <XAxis dataKey="date" tickLine={false} axisLine={false} fontSize={11} stroke="#8a8a85" />
          <YAxis domain={[0, 100]} tickLine={false} axisLine={false} fontSize={11} stroke="#8a8a85" />
          <Tooltip
            cursor={{ stroke: "#343432", strokeWidth: 1 }}
            contentStyle={{ background: "#141414", border: "1px solid #343432", borderRadius: 2, color: "#f5f5f0" }}
          />
          <Area
            dataKey="score"
            name="Security score"
            type="linear"
            stroke="var(--primary)"
            strokeWidth={2}
            fill="var(--primary)"
            fillOpacity={0.08}
            isAnimationActive={false}
            dot={{ r: 3, fill: "#0a0a0a", stroke: "var(--primary)", strokeWidth: 2 }}
            activeDot={{ r: 4, fill: "var(--primary)", stroke: "#0a0a0a", strokeWidth: 1 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
