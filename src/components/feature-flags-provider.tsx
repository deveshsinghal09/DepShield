"use client";

import { createContext, useContext, type ReactNode } from "react";
import type { FeatureFlags } from "@/lib/feature-flags";

const SAFE_DEFAULTS: FeatureFlags = {
  aiAnalyst: false,
  reachability: false,
  remediationSandbox: false,
  policyEngine: false,
  attackReplay: false,
  sourceUploads: false,
  nvdProvider: false,
  githubAdvisoryProvider: false,
};

const FeatureFlagsContext = createContext<FeatureFlags>(SAFE_DEFAULTS);

export function FeatureFlagsProvider({
  children,
  flags,
}: {
  children: ReactNode;
  flags: FeatureFlags;
}) {
  return (
    <FeatureFlagsContext.Provider value={flags}>
      {children}
    </FeatureFlagsContext.Provider>
  );
}

export function useFeatureFlags() {
  return useContext(FeatureFlagsContext);
}
