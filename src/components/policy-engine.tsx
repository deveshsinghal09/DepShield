"use client";

import { useMemo, useState } from "react";
import { CheckCircle2, CircleAlert, LoaderCircle, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DEFAULT_SECURITY_POLICY, evaluateSecurityPolicy, type SecurityPolicy } from "@/lib/policy";
import type { Scan } from "@/lib/types";

type PolicyEngineProps = {
  scan: Scan;
  previous?: Scan;
  initialPolicy?: SecurityPolicy;
};

export function PolicyEngine({ scan, previous, initialPolicy }: PolicyEngineProps) {
  const [policy, setPolicy] = useState<SecurityPolicy>({
    ...DEFAULT_SECURITY_POLICY,
    ...(initialPolicy ?? {}),
  });
  const [evaluation, setEvaluation] = useState(() => evaluateSecurityPolicy(scan, policy, previous));
  const [saveState, setSaveState] = useState<{ kind: "idle" | "saving" | "saved" | "error"; message?: string }>({ kind: "idle" });
  const preview = useMemo(() => evaluateSecurityPolicy(scan, policy, previous), [scan, previous, policy]);
  const tone = evaluation.status === "pass"
    ? "text-safe"
    : evaluation.status === "fail"
      ? "text-destructive"
      : "text-warning";
  const Icon = evaluation.status === "pass" ? CheckCircle2 : evaluation.status === "fail" ? ShieldX : CircleAlert;

  function numberField<K extends keyof SecurityPolicy>(key: K, value: string) {
    setPolicy((current) => ({ ...current, [key]: value === "" ? null : Number(value) }));
  }

  async function evaluateAndSave() {
    setSaveState({ kind: "saving", message: "Saving policy to the local evidence ledger…" });
    try {
      const response = await fetch("/api/policies", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(policy),
      });
      const body = await response.json().catch(() => null) as { data?: SecurityPolicy; error?: { message?: string } } | null;
      if (!response.ok || !body?.data) throw new Error(body?.error?.message ?? `Policy save failed with HTTP ${response.status}.`);
      setEvaluation(preview);
      setSaveState({ kind: "saved", message: "Policy saved. The displayed result and CI gate now use these thresholds." });
    } catch (error) {
      setSaveState({ kind: "error", message: error instanceof Error ? error.message : "The policy could not be saved." });
    }
  }

  return (
    <section className="surface surface-outline" data-ui="policy-engine">
      <div className="grid xl:grid-cols-[380px_minmax(0,1fr)]">
        <form
          className="border-b p-5 xl:border-b-0 xl:border-r"
          onSubmit={(event) => {
            event.preventDefault();
            void evaluateAndSave();
          }}
        >
          <div>
            <h2 className="font-bold">Production Security Gate</h2>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Configure deterministic policy thresholds. Saved locally in the DepShield SQLite ledger.
            </p>
          </div>
          <div className="mt-6 space-y-4">
            <label className="flex items-start gap-3 rounded-sm border bg-background p-3 text-sm">
              <input
                type="checkbox"
                checked={policy.blockReachableCritical}
                onChange={(event) => setPolicy((current) => ({
                  ...current,
                  blockReachableCritical: event.target.checked,
                }))}
                className="mt-0.5 size-4 accent-[var(--primary)]"
              />
              <span>
                <b className="block text-foreground">Block reachable critical findings</b>
                <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                  Warn when critical findings exist but source reachability was not assessed.
                </span>
              </span>
            </label>
            <PolicyInput
              label="Minimum security score"
              value={policy.minimumSecurityScore}
              min={0}
              max={100}
              onChange={(value) => numberField("minimumSecurityScore", value)}
            />
            <PolicyInput
              label="Maximum critical findings"
              value={policy.maximumCriticalFindings}
              min={0}
              max={100}
              onChange={(value) => numberField("maximumCriticalFindings", value)}
            />
            <PolicyInput
              label="Block no-fix findings at CVSS"
              value={policy.blockNoFixAtOrAboveCvss ?? ""}
              min={0}
              max={10}
              step={0.1}
              onChange={(value) => numberField("blockNoFixAtOrAboveCvss", value)}
            />
            <PolicyInput
              label="Maximum newly introduced critical findings"
              value={policy.maximumNewCriticalFindings ?? ""}
              min={0}
              max={100}
              onChange={(value) => numberField("maximumNewCriticalFindings", value)}
            />
            <label className="block text-xs text-muted-foreground">
              Incomplete source action
              <select
                value={policy.incompleteSourceAction}
                onChange={(event) => setPolicy((current) => ({
                  ...current,
                  incompleteSourceAction: event.target.value as "warning" | "fail",
                }))}
                className="mt-2 h-10 w-full rounded-sm border bg-background px-3 text-sm text-foreground"
              >
                <option value="warning">Warning</option>
                <option value="fail">Fail</option>
              </select>
            </label>
          </div>
          <Button className="mt-6 w-full" type="submit" disabled={saveState.kind === "saving"}>
            {saveState.kind === "saving" ? <LoaderCircle className="animate-spin" size={15} /> : null}
            {saveState.kind === "saving" ? "Saving policy…" : "Evaluate and save policy"}
          </Button>
          {saveState.message ? (
            <p
              className={`mt-3 text-xs leading-5 ${saveState.kind === "error" ? "text-destructive" : saveState.kind === "saved" ? "text-safe" : "text-muted-foreground"}`}
              role={saveState.kind === "error" ? "alert" : "status"}
            >
              {saveState.message}
            </p>
          ) : null}
        </form>

        <div>
          <div className="flex flex-col gap-4 border-b p-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <Icon className={tone} size={24} />
              <div>
                <span className="text-xs text-muted-foreground">Current result</span>
                <h3 className={`data mt-1 text-2xl font-bold ${tone}`}>{evaluation.status.toUpperCase()}</h3>
              </div>
            </div>
            <div className="data rounded-sm bg-background px-4 py-3 text-xs ring-1 ring-border">
              CI exit code <b className={tone}>{evaluation.exitCode}</b>
            </div>
          </div>
          <div className="divide-y">
            {evaluation.rules.map((rule) => (
              <article key={rule.id} className="p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h4 className="font-semibold">{rule.label}</h4>
                  <span className={`data text-xs font-bold ${rule.status === "pass" ? "text-safe" : rule.status === "fail" ? "text-destructive" : "text-warning"}`}>
                    {rule.status.toUpperCase()}
                  </span>
                </div>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{rule.reason}</p>
                {rule.evidence.length ? (
                  <details className="mt-3">
                    <summary className="cursor-pointer text-xs font-semibold text-primary">
                      Evidence ({rule.evidence.length})
                    </summary>
                    <ul className="data mt-2 space-y-1 break-words text-xs text-muted-foreground">
                      {rule.evidence.slice(0, 12).map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
                    </ul>
                  </details>
                ) : null}
              </article>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

type PolicyInputProps = {
  label: string;
  value: number | string;
  onChange: (value: string) => void;
  min?: number;
  max?: number;
  step?: number;
};

function PolicyInput({ label, value, onChange, ...input }: PolicyInputProps) {
  return (
    <label className="block text-xs text-muted-foreground">
      {label}
      <input
        type="number"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="data mt-2 h-10 w-full rounded-sm border bg-background px-3 text-sm text-foreground"
        {...input}
      />
    </label>
  );
}
