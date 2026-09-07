"use client";

import { TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <section className="surface surface-outline hud-panel grid min-h-[420px] place-items-center p-10 text-center" data-ui="error-state">
      <div>
        <span className="hud-label text-destructive">E_VIEW_LOAD // 500</span>
        <span className="mx-auto mt-4 grid size-12 place-items-center border border-destructive/50 text-destructive"><TriangleAlert /></span>
        <h2 className="mt-4 text-lg font-extrabold">This security view could not load</h2>
        <p className="mt-2 text-muted-foreground">The saved scan may be unavailable. Retry, or run a new scan.</p>
        <Button className="mt-5" onClick={reset}>Retry view</Button>
      </div>
    </section>
  );
}
