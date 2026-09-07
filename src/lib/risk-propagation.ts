import type { Dependency, RiskPropagation } from "./types";

export const RISK_PROPAGATION_MODEL = {
  version: "DepShield Propagation v1",
  distanceDecay: 0.55,
  reachableWeight: 1,
  possiblyReachableWeight: 0.72,
  notObservedWeight: 0.35,
  unknownWeight: 0.5,
  devWeight: 0.45,
  exposedWeight: 1,
  internalWeight: 0.75,
} as const;

export function applyRiskPropagation(items: Dependency[]): Dependency[] {
  return items.map((item) => ({ ...item, propagation: propagationFor(item, items) }));
}

export function propagationFor(item: Dependency, items: Dependency[]): RiskPropagation {
  const node = `${item.name}@${item.version}`;
  const contributors = items
    .filter((candidate) => candidate.risk > 0 && candidate !== item)
    .flatMap((candidate) => {
      const itemPaths = item.paths ?? [];
      const matchingPaths = (candidate.paths ?? []).flatMap((path) => {
        const exactInstance = itemPaths
          .filter((parentPath) => parentPath.nodes.length < path.nodes.length && isNodePrefix(parentPath.nodes, path.nodes))
          .map((parentPath) => ({ path, distance: path.nodes.length - parentPath.nodes.length }));
        if (exactInstance.length) return exactInstance;
        // Legacy scan snapshots may not contain structured paths. Only those
        // snapshots fall back to a name@version lookup.
        if (itemPaths.length) return [];
        const parentIndex = path.nodes.indexOf(node);
        return parentIndex >= 0 && parentIndex < path.nodes.length - 1
          ? [{ path, distance: path.nodes.length - 1 - parentIndex }]
          : [];
      });
      if (!matchingPaths.length) return [];

      const distance = Math.max(1, Math.min(...matchingPaths.map((value) => value.distance)));
      const baseRisk = candidate.contextual?.finalPriority ?? candidate.risk;
      const reachabilityWeight = reachabilityWeightFor(candidate);
      const runtimeWeight = candidate.runtime === false ? RISK_PROPAGATION_MODEL.devWeight : 1;
      const exposureWeight = candidate.reachability?.internetExposed
        ? RISK_PROPAGATION_MODEL.exposedWeight
        : RISK_PROPAGATION_MODEL.internalWeight;
      const pathWeight = Math.min(1.25, 1 + Math.log2(matchingPaths.length) * 0.08);
      const contribution = clamp(
        baseRisk *
          Math.pow(RISK_PROPAGATION_MODEL.distanceDecay, distance) *
          reachabilityWeight *
          runtimeWeight *
          exposureWeight *
          pathWeight,
      );

      return [{
        dependency: `${candidate.name}@${candidate.version}`,
        distance,
        pathCount: matchingPaths.length,
        contribution,
        explanation:
          `${baseRisk} child priority × ${RISK_PROPAGATION_MODEL.distanceDecay}^${distance} distance decay` +
          ` × ${reachabilityWeight.toFixed(2)} reachability × ${runtimeWeight.toFixed(2)} runtime` +
          ` × ${exposureWeight.toFixed(2)} exposure × ${pathWeight.toFixed(2)} path weight`,
      }];
    })
    .toSorted((a, b) => b.contribution - a.contribution);

  // Bounded union prevents shared dependency paths from being added repeatedly.
  const inheritedRisk = clamp(
    100 * (1 - contributors.reduce((product, contributor) => product * (1 - contributor.contribution / 100), 1)),
  );
  const ownRisk = item.contextual?.finalPriority ?? item.risk;
  const contextualRisk = clamp(100 * (1 - (1 - ownRisk / 100) * (1 - inheritedRisk / 100)));

  return {
    ownRisk,
    inheritedRisk,
    contextualRisk,
    contributors,
    formula:
      "Each descendant contribution = child priority × 0.55^distance × reachability × runtime × exposure × bounded path weight. Contributions use a bounded union; this is a DepShield heuristic, not an industry standard.",
  };
}

function isNodePrefix(prefix: string[], value: string[]) {
  return prefix.every((node, index) => value[index] === node);
}

function reachabilityWeightFor(item: Dependency) {
  switch (item.reachability?.status) {
    case "REACHABLE":
      return RISK_PROPAGATION_MODEL.reachableWeight;
    case "POSSIBLY_REACHABLE":
      return RISK_PROPAGATION_MODEL.possiblyReachableWeight;
    case "NOT_OBSERVED":
      return RISK_PROPAGATION_MODEL.notObservedWeight;
    default:
      return RISK_PROPAGATION_MODEL.unknownWeight;
  }
}

function clamp(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}
