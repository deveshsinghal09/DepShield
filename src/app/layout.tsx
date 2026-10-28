import type { Metadata } from "next";
import { Suspense } from "react";
import "./globals.css";
import "@fontsource-variable/archivo";
import "@fontsource-variable/jetbrains-mono";
import "@fontsource/anton";
import "@/components/security/security.css";
import "@/components/dashboard/dashboard.css";
import { AppShell } from "@/components/app-shell";
import { FeatureFlagsProvider } from "@/components/feature-flags-provider";
import { getFeatureFlags } from "@/lib/feature-flags";

export const metadata: Metadata = {
  title: { default: "DepShield AI", template: "%s · DepShield AI" },
  description: "Context-aware open-source dependency risk intelligence and remediation platform.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const featureFlags = getFeatureFlags();
  return (
    <html lang="en" className="dark" data-scroll-behavior="smooth">
      <body>
        <FeatureFlagsProvider flags={featureFlags}>
          <Suspense><AppShell>{children}</AppShell></Suspense>
        </FeatureFlagsProvider>
      </body>
    </html>
  );
}
