import Link from "next/link";
import { ShieldOff } from "lucide-react";

export function FeatureUnavailable({
  feature,
  description,
  flag,
}: {
  feature: string;
  description: string;
  flag: string;
}) {
  return (
    <section
      className="surface surface-outline grid min-h-[360px] place-items-center p-8 text-center sm:p-10"
      data-ui="feature-unavailable"
    >
      <div>
        <span className="mx-auto grid size-12 place-items-center border text-muted-foreground">
          <ShieldOff size={21} />
        </span>
        <h2 className="mt-4 text-lg font-bold">{feature} is disabled</h2>
        <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-muted-foreground">
          {description}
        </p>
        <p className="data mx-auto mt-4 max-w-lg rounded-sm bg-background px-3 py-2 text-xs text-muted-foreground ring-1 ring-border">
          A trusted operator can enable <b className="text-foreground">{flag}</b> and restart the service.
        </p>
        <Link
          href="/"
          className="mt-5 inline-flex h-10 items-center justify-center rounded-sm border bg-transparent px-4 text-sm font-semibold hover:bg-secondary"
        >
          Return to command center
        </Link>
      </div>
    </section>
  );
}
