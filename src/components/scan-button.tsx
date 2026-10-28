"use client";
import Link from "next/link";
import { ScanLine } from "lucide-react";
export function ScanButton() {
  return <Link href="/scan" data-ui="scan-button" className="inline-flex h-10 min-w-32 items-center justify-center gap-2 rounded-xl bg-primary px-4 text-sm font-bold text-primary-foreground hover:opacity-90"><ScanLine size={16} />Scan project</Link>;
}
