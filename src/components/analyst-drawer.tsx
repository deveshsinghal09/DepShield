"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { BrainCircuit, LoaderCircle, Send, ShieldOff, ShieldQuestion, X } from "lucide-react";
import type { AnalystAnswer } from "@/lib/types";
import { ANALYST_QUESTION_EVENT, type AnalystQuestionEventDetail } from "@/lib/analyst-events";
import { useFeatureFlags } from "@/components/feature-flags-provider";
import { Button } from "@/components/ui/button";
import { Sheet } from "@/components/ui/sheet";

const suggestions = [
  "Which vulnerability should I fix first?",
  "Why is the top dependency ranked first?",
  "Which finding is closest to an internet-facing route?",
  "Give me a remediation plan for the next sprint.",
];

export function AnalystDrawer() {
  const { aiAnalyst } = useFeatureFlags();
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scan") ?? undefined;
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<AnalystAnswer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  const runQuestion = useCallback(async (prompt: string) => {
    if (!aiAnalyst) {
      setOpen(true);
      setError("The evidence-grounded Analyst is disabled for this deployment.");
      return;
    }
    setQuestion(prompt);
    setAnswer(null);
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/analyst", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ scanId, question: prompt }),
      });
      const body = await response.json().catch(() => null) as {
        data?: AnalystAnswer;
        error?: { message?: string };
      } | null;
      if (!response.ok || !body?.data) throw new Error(body?.error?.message ?? "The analyst could not answer this question.");
      setAnswer(body.data);
    } catch (value) {
      setError(value instanceof Error ? value.message : "The analyst could not answer this question.");
    } finally {
      setLoading(false);
    }
  }, [aiAnalyst, scanId]);

  async function ask(value = question) {
    const prompt = value.trim();
    if (!prompt || loading) return;
    await runQuestion(prompt);
  }

  useEffect(() => {
    const handleQuestion = (event: Event) => {
      const prompt = (event as CustomEvent<AnalystQuestionEventDetail>).detail?.question?.trim();
      if (!prompt) return;
      setOpen(true);
      void runQuestion(prompt.slice(0, 500));
    };
    window.addEventListener(ANALYST_QUESTION_EVENT, handleQuestion);
    return () => window.removeEventListener(ANALYST_QUESTION_EVENT, handleQuestion);
  }, [runQuestion]);

  return (
    <div data-ui="ai-analyst">
      <Button
        variant="outline"
        size="sm"
        onClick={() => setOpen(true)}
        aria-haspopup="dialog"
        aria-controls="analyst-dialog"
        aria-expanded={open}
        title={aiAnalyst ? "Ask the evidence-grounded Analyst" : "Analyst disabled for this deployment"}
      >
        <BrainCircuit size={15} />
        <span className="hidden sm:inline">{aiAnalyst ? "Ask Analyst" : "Analyst off"}</span>
      </Button>
      <Sheet
        id="analyst-dialog"
        open={open}
        onOpenChange={setOpen}
        labelledBy="analyst-title"
        describedBy="analyst-description"
        initialFocusRef={closeButtonRef}
        panelClassName="max-w-xl"
        dataUi="analyst-sheet"
      >
        <header className="flex items-start justify-between border-b p-5 sm:p-6">
          <div className="flex gap-3">
            <span className="grid size-10 shrink-0 place-items-center border border-primary/40 text-primary">
              <BrainCircuit size={20} />
            </span>
            <div>
              <h2 id="analyst-title" className="font-bold tracking-[-.02em]">DepShield Analyst</h2>
              <p id="analyst-description" className="mt-1 text-xs leading-5 text-muted-foreground">
                {aiAnalyst ? "Answers only from persisted scan evidence. No exploit generation." : "Disabled by this deployment's feature policy."}
              </p>
            </div>
          </div>
          <button ref={closeButtonRef} className="rounded-sm p-2 text-muted-foreground hover:bg-secondary" onClick={() => setOpen(false)} aria-label="Close analyst">
            <X size={18} />
          </button>
        </header>
        <div className="scrollbar flex-1 overflow-y-auto p-5 sm:p-6">
          {!aiAnalyst ? (
            <section className="grid min-h-64 place-items-center text-center" data-ui="analyst-disabled">
              <div>
                <span className="mx-auto grid size-12 place-items-center border text-muted-foreground">
                  <ShieldOff size={20} />
                </span>
                <h3 className="mt-4 font-semibold">Analyst unavailable</h3>
                <p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-muted-foreground">
                  A trusted operator can enable <span className="data text-foreground">ENABLE_AI_ANALYST</span> and restart the service. Core deterministic scan evidence remains available.
                </p>
              </div>
            </section>
          ) : null}
          {aiAnalyst && !answer && !loading ? (
            <section>
              <div className="flex gap-3 rounded-[2px] border bg-secondary/70 p-4">
                <ShieldQuestion className="mt-0.5 shrink-0 text-primary" size={18} />
                <p className="text-sm leading-6 text-muted-foreground">Ask about ranking, evidence, paths, fixes, compatibility estimates, or differences supported by the selected scan.</p>
              </div>
              <div className="mt-5 space-y-2">
                {suggestions.map((suggestion) => (
                  <button key={suggestion} type="button" className="w-full rounded-sm bg-background p-3 text-left text-sm ring-1 ring-border hover:bg-secondary" onClick={() => ask(suggestion)}>
                    {suggestion}
                  </button>
                ))}
              </div>
            </section>
          ) : null}
          {aiAnalyst && loading ? (
            <div className="grid min-h-52 place-items-center" role="status">
              <div className="text-center text-muted-foreground"><LoaderCircle className="mx-auto mb-3 animate-spin text-primary" /><p className="text-sm">Retrieving scan evidence…</p></div>
            </div>
          ) : null}
          {aiAnalyst && answer && !loading ? (
            <article className="space-y-5">
              <div>
                <span className="text-xs font-semibold text-primary">Grounded response</span>
                <p className="mt-3 whitespace-pre-wrap text-sm leading-7 text-secondary-foreground">{answer.answer}</p>
              </div>
              <div>
                <h3 className="text-xs font-semibold">Evidence citations</h3>
                {answer.citations.length ? (
                  <ul className="mt-3 space-y-2">
                    {answer.citations.map((citation, index) => (
                      <li key={`${citation.label}-${citation.value}-${index}`} className="data rounded-sm bg-background px-3 py-2 text-xs text-muted-foreground ring-1 ring-border">
                        [{citation.label}: {citation.value}]
                      </li>
                    ))}
                  </ul>
                ) : <p className="mt-2 text-xs text-muted-foreground">No supporting citation was available.</p>}
              </div>
              <p className="text-xs text-muted-foreground">
                Provider: {answer.provider === "gemini"
                  ? "Google Gemini · evidence validated"
                  : answer.provider === "external"
                    ? "configured AI · evidence validated"
                    : "deterministic local fallback"}
              </p>
            </article>
          ) : null}
          {aiAnalyst && error ? <div role="alert" className="rounded-sm bg-destructive/10 p-4 text-sm text-destructive ring-1 ring-destructive/30">{error}</div> : null}
        </div>
        <form className="border-t p-4 sm:p-5" onSubmit={(event) => { event.preventDefault(); ask(); }}>
          <label className="sr-only" htmlFor="analyst-question">Question for DepShield Analyst</label>
          <div className="flex gap-2">
            <input id="analyst-question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder={aiAnalyst ? "Ask about this scan…" : "Analyst disabled"} disabled={!aiAnalyst} className="h-10 min-w-0 flex-1 rounded-sm border bg-background px-3 text-sm placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-60" maxLength={500} />
            <Button type="submit" disabled={!aiAnalyst || loading || !question.trim()} aria-label="Ask analyst"><Send size={15} /></Button>
          </div>
        </form>
      </Sheet>
    </div>
  );
}
