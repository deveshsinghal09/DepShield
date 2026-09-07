export type FeatureFlags = {
  aiAnalyst: boolean;
  reachability: boolean;
  remediationSandbox: boolean;
  policyEngine: boolean;
  attackReplay: boolean;
  sourceUploads: boolean;
  nvdProvider: boolean;
  githubAdvisoryProvider: boolean;
};

function enabled(value: string | undefined, defaultValue: boolean) {
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === "true";
}

export function getFeatureFlags(): FeatureFlags {
  return {
    aiAnalyst: enabled(process.env.ENABLE_AI_ANALYST, true),
    reachability: enabled(process.env.ENABLE_REACHABILITY, true),
    remediationSandbox: enabled(process.env.ENABLE_REMEDIATION_SANDBOX, true),
    policyEngine: enabled(process.env.ENABLE_POLICY_ENGINE, true),
    attackReplay: enabled(process.env.ENABLE_ATTACK_REPLAY ?? process.env.DEPSHIELD_ENABLE_ATTACK_REPLAY, process.env.NODE_ENV !== "production"),
    sourceUploads: enabled(process.env.ENABLE_SOURCE_UPLOADS, process.env.NODE_ENV !== "production"),
    nvdProvider: enabled(process.env.ENABLE_NVD_PROVIDER, false),
    githubAdvisoryProvider: enabled(process.env.ENABLE_GITHUB_ADVISORY_PROVIDER, false),
  };
}
