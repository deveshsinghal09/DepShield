"use client";

import { useEffect, useRef, useState } from "react";

export function HumanScan() {
  const canvas = useRef<HTMLCanvasElement>(null);
  const scene = useRef<Awaited<ReturnType<typeof import("@/lib/human-scan-scene").init>> | null>(null);
  const [status, setStatus] = useState("Loading human scan…");
  const [paused, setPaused] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    import("@/lib/human-scan-scene").then(async ({ init }) => {
      if (controller.signal.aborted || !canvas.current) return;
      const handle = await init(canvas.current, controller.signal);
      if (controller.signal.aborted) { handle.dispose(); return; }
      scene.current = handle;
      setPaused(matchMedia("(prefers-reduced-motion: reduce)").matches);
      setStatus("");
    }).catch((error: unknown) => {
      if (!controller.signal.aborted) setStatus(error instanceof Error ? "3D preview unavailable on this browser. Scanning is still available." : "3D preview unavailable.");
    });
    return () => { controller.abort(); scene.current?.dispose(); scene.current = null; };
  }, []);
  return <div className="human-scan" data-ui="human-scan">
    <canvas ref={canvas} aria-label="Interactive 3D human head rendered as a wireframe and particle scan" />
    {status ? <p className="human-scan-status" role="status">{status}</p> : null}
    <span className="human-scan-label" aria-hidden="true">SURFACE / HUMAN SCAN<br />18,000 PARTICLES</span>
    <div className="human-scan-controls">
      {!status ? <button onClick={() => { scene.current?.setPaused(!paused); setPaused(!paused); }} aria-pressed={paused}>{paused ? "Resume motion" : "Pause motion"}</button> : null}
      <a href="/models/ATTRIBUTION.md" target="_blank" rel="noreferrer">Model credit</a>
    </div>
  </div>;
}
