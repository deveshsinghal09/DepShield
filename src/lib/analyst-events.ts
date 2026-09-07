"use client";

export const ANALYST_QUESTION_EVENT = "depshield:analyst-question";

export type AnalystQuestionEventDetail = {
  question: string;
};

export function requestFixExplanation(input: {
  name: string;
  version: string;
  targetVersion?: string;
}) {
  const target = input.targetVersion ? ` to ${input.targetVersion}` : "";
  const question = `Explain this fix for ${input.name}@${input.version}${target}. Why upgrade, which findings would disappear, what might break, and what should I test?`;
  window.dispatchEvent(new CustomEvent<AnalystQuestionEventDetail>(ANALYST_QUESTION_EVENT, {
    detail: { question },
  }));
}
