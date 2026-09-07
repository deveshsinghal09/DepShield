import { cn } from "@/lib/utils";

export function GradeBadge({ grade, large = false }: { grade: string; large?: boolean }) {
  const tone = grade === "A" || grade === "B" ? "border-safe text-safe" : grade === "C" ? "border-warning text-warning" : "border-critical text-critical";
  return (
    <span className={cn("data inline-grid place-items-center border font-black", tone, large ? "size-24 text-6xl" : "size-9 text-xl")} aria-label={`Security grade ${grade}`}>
      {grade}
    </span>
  );
}
