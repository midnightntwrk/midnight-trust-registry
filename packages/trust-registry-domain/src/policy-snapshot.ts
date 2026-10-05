import { z } from "zod";

import { HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";
import {
  GovernanceDecisionFamilySchema,
  GovernancePolicyRecordSchema,
  type GovernancePolicyRecord,
} from "./types.js";

const VersionSchema = z.string().regex(/^v[1-9][0-9]*$/u);
const TimestampSchema = z.string().datetime({ offset: true });
const CanonicalIdentifierSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Scoped identifiers must be lowercase",
);
const ThresholdSchema = z.strictObject({
  family: GovernanceDecisionFamilySchema,
  threshold: z.number().int().min(1).max(5),
});
const requiredFamilies = ["maintainer", "member", "emergency", "archival"] as const;

export const GovernancePolicySnapshotSchema = z.strictObject({
  format: z.literal("tr-policy-snapshot-v1"),
  registryId: CanonicalIdentifierSchema,
  policyId: CanonicalIdentifierSchema,
  policyVersion: VersionSchema,
  effectiveFrom: TimestampSchema,
  effectiveUntil: TimestampSchema.nullable(),
  contentCommitment: HashHexSchema.regex(/^0x[0-9a-f]{64}$/u),
  thresholds: z.array(ThresholdSchema).min(4).max(5),
}).superRefine((snapshot, ctx) => {
  const families = new Set<string>();
  for (const [index, threshold] of snapshot.thresholds.entries()) {
    if (families.has(threshold.family)) {
      ctx.addIssue({ code: "custom", path: ["thresholds", index, "family"], message: "Duplicate decision family" });
    }
    families.add(threshold.family);
  }
  for (const family of requiredFamilies) {
    if (!families.has(family)) {
      ctx.addIssue({ code: "custom", path: ["thresholds"], message: `Missing ${family} threshold` });
    }
  }
  const defaultThreshold = snapshot.thresholds.find(({ family }) => family === "member")?.threshold;
  for (const family of ["maintainer", "auditor"] as const) {
    const threshold = snapshot.thresholds.find((candidate) => candidate.family === family)?.threshold;
    if (threshold !== undefined && defaultThreshold !== undefined && threshold !== defaultThreshold) {
      ctx.addIssue({ code: "custom", path: ["thresholds"], message: `${family} must use the Compact default threshold` });
    }
  }
  if (snapshot.effectiveUntil !== null && Date.parse(snapshot.effectiveUntil) < Date.parse(snapshot.effectiveFrom)) {
    ctx.addIssue({ code: "custom", path: ["effectiveUntil"], message: "Policy window must not end before it starts" });
  }
});

export type GovernancePolicySnapshot = z.infer<typeof GovernancePolicySnapshotSchema>;

export function deriveGovernancePolicySnapshot(policy: GovernancePolicyRecord): GovernancePolicySnapshot {
  const parsed = GovernancePolicyRecordSchema.parse(policy);
  const content = {
    policyUri: parsed.policyUri,
    policyTemplates: parsed.policyTemplates.map((template) => ({
      ...template,
      applicableRoles: sortedUnique(template.applicableRoles),
      applicableActionKinds: sortedUnique(template.applicableActionKinds),
      evidenceRules: sortedUnique(template.evidenceRules),
    })).sort((a, b) => compareIds(a.family, b.family)),
    decisionBindings: parsed.decisionBindings.map((binding) => ({
      ...binding,
      actionScopes: sortedUnique(binding.actionScopes),
    })).sort((a, b) => compareIds(a.family, b.family)),
    decisionRules: sortedUnique(parsed.decisionRules),
    disputeRules: sortedUnique(parsed.disputeRules),
    retentionRules: sortedUnique(parsed.retentionRules),
    emergencyRules: sortedUnique(parsed.emergencyRules),
  };
  return GovernancePolicySnapshotSchema.parse({
    format: "tr-policy-snapshot-v1",
    registryId: parsed.registryId,
    policyId: parsed.policyId,
    policyVersion: parsed.version,
    effectiveFrom: parsed.effectiveFrom,
    effectiveUntil: parsed.effectiveUntil ?? parsed.supersededAt ?? null,
    contentCommitment: sha256Hex(canonicalizeJson(content)),
    thresholds: parsed.policyTemplates.map((template) => ({
      family: template.family,
      threshold: template.requiredMaintainerThreshold,
    })),
  });
}

export function canonicalizeGovernancePolicySnapshot(snapshot: GovernancePolicySnapshot): string {
  const parsed = GovernancePolicySnapshotSchema.parse(snapshot);
  return canonicalizeJson({
    ...parsed,
    effectiveFrom: new Date(parsed.effectiveFrom).toISOString(),
    effectiveUntil: parsed.effectiveUntil === null ? null : new Date(parsed.effectiveUntil).toISOString(),
    thresholds: [...parsed.thresholds].sort((a, b) => compareIds(a.family, b.family)),
  });
}

export function computeGovernancePolicySnapshotCommitment(snapshot: GovernancePolicySnapshot): string {
  return sha256Hex(canonicalizeGovernancePolicySnapshot(snapshot));
}

export function assertGovernancePolicySnapshotMatchesRecord(
  policy: GovernancePolicyRecord,
  snapshot: GovernancePolicySnapshot,
): void {
  const expected = deriveGovernancePolicySnapshot(policy);
  if (computeGovernancePolicySnapshotCommitment(snapshot) !== computeGovernancePolicySnapshotCommitment(expected)) {
    throw new Error("Policy snapshot does not match the source policy record");
  }
}

export function assertGovernancePolicyRevision(
  previous: GovernancePolicySnapshot,
  next: GovernancePolicySnapshot,
): void {
  const oldSnapshot = GovernancePolicySnapshotSchema.parse(previous);
  const newSnapshot = GovernancePolicySnapshotSchema.parse(next);
  if (oldSnapshot.registryId !== newSnapshot.registryId || oldSnapshot.policyId !== newSnapshot.policyId) {
    throw new Error("Policy revision must retain registry and policy identity");
  }
  const oldVersion = Number(oldSnapshot.policyVersion.slice(1));
  const newVersion = Number(newSnapshot.policyVersion.slice(1));
  if (!Number.isSafeInteger(oldVersion) || !Number.isSafeInteger(newVersion) || newVersion <= oldVersion) {
    throw new Error("Policy revision must increase the policy version");
  }
  if (oldSnapshot.effectiveUntil === null || Date.parse(oldSnapshot.effectiveUntil) > Date.parse(newSnapshot.effectiveFrom)) {
    throw new Error("Previous policy window must close before the revision begins");
  }
}

export function assertMaintainerThresholdsRemainSatisfiable(
  activeMaintainersAfterTransition: number,
  snapshot: GovernancePolicySnapshot,
): void {
  const parsed = GovernancePolicySnapshotSchema.parse(snapshot);
  if (!Number.isSafeInteger(activeMaintainersAfterTransition) || activeMaintainersAfterTransition < 1) {
    throw new Error("Active maintainer count must be a positive integer");
  }
  if (parsed.thresholds.some(({ threshold }) => threshold > activeMaintainersAfterTransition)) {
    throw new Error("Maintainer transition would leave a configured threshold unsatisfied");
  }
}

function sortedUnique(values: readonly string[]): string[] {
  if (new Set(values).size !== values.length) throw new Error("Policy set contains duplicate values");
  return [...values].sort(compareIds);
}

function compareIds(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("Policy snapshot must contain JSON values only");
}
