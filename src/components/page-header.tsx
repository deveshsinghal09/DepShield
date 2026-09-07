import type { ReactNode } from "react";

export function PageHeader({ title, description, action, label }: {
  title: string; description: string; action?: ReactNode; label?: string;
}) {
  return <header className="route-heading" data-ui="page-header">
    <div className="min-w-0">
      {label ? <span className="hud-label text-primary">{label}</span> : null}
      <h1>{title}</h1>
      <p>{description}</p>
    </div>
    {action ? <div className="route-heading-actions">{action}</div> : null}
  </header>;
}
