import { describe, expect, it } from "vitest";

import {
  assertGovernancePolicyRevision,
  assertGovernancePolicySnapshotMatchesRecord,
  assertMaintainerThresholdsRemainSatisfiable,
  canonicalizeGovernancePolicySnapshot,
  computeGovernancePolicySnapshotCommitment,
  deriveGovernancePolicySnapshot,
  GovernancePolicyRecordSchema,
  GovernancePolicySnapshotSchema,
} from "../index.js";

const families = ["maintainer", "member", "emergency", "archival"] as const;

function policy(version = "v1", threshold = 2) {
  return GovernancePolicyRecordSchema.parse({
    policyId: "policy:kanon",
    registryId: "registry:midnight:kanon",
    version,
    policyUri: "https://registry.example/policy",
    status: "active",
    effectiveFrom: "2026-10-05T00:00:00Z",
    effectiveUntil: "2026-11-05T00:00:00Z",
    policyTemplates: families.map((family) => ({
      templateId: `template:${family}`,
      family,
      name: `${family} governance`,
      description: `${family} decisions`,
      requiredMaintainerThreshold: threshold,
      applicableRoles: ["maintainer"],
      applicableActionKinds: [`tr:${family}:authorize`],
      evidenceRules: ["quorum signatures", "application evidence"],
    })),
    decisionBindings: families.map((family) => ({
      bindingId: `binding:${family}`,
      family,
      templateId: `template:${family}`,
      actionScopes: [`${family}-authorization`],
    })),
    decisionRules: ["majority maintainers"],
    disputeRules: ["appeal"],
    retentionRules: ["retain history"],
    emergencyRules: ["incident evidence"],
    lifecycleEventRoot: "0x" + "a".repeat(64),
  });
}

describe("governance policy snapshot v1", () => {
  it("publishes a stable canonical JSON and SHA-256 vector", () => {
    const snapshot = GovernancePolicySnapshotSchema.parse({
      format: "tr-policy-snapshot-v1",
      registryId: "registry:midnight:kanon",
      policyId: "policy:kanon",
      policyVersion: "v1",
      effectiveFrom: "2026-10-05T08:00:00+08:00",
      effectiveUntil: null,
      contentCommitment: "0x" + "a".repeat(64),
      thresholds: families.map((family) => ({ family, threshold: 2 })),
    });
    expect(canonicalizeGovernancePolicySnapshot(snapshot)).toBe(
      '{"contentCommitment":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","effectiveFrom":"2026-10-05T00:00:00.000Z","effectiveUntil":null,"format":"tr-policy-snapshot-v1","policyId":"policy:kanon","policyVersion":"v1","registryId":"registry:midnight:kanon","thresholds":[{"family":"archival","threshold":2},{"family":"emergency","threshold":2},{"family":"maintainer","threshold":2},{"family":"member","threshold":2}]}',
    );
    expect(computeGovernancePolicySnapshotCommitment(snapshot)).toBe(
      "0x29485cb6d7192cdc2d70a9843fb2f3364ffadaa0e2de5a8f839db40b15b9852c",
    );
  });

  it("commits the four 2-of-3 decision families and canonical policy content", () => {
    const snapshot = deriveGovernancePolicySnapshot(policy());
    expect(snapshot.thresholds).toHaveLength(4);
    expect(snapshot.thresholds.every(({ threshold }) => threshold === 2)).toBe(true);
    expect(canonicalizeGovernancePolicySnapshot(snapshot)).toContain('"policyVersion":"v1"');
    expect(computeGovernancePolicySnapshotCommitment(snapshot)).toMatch(/^0x[0-9a-f]{64}$/);
    expect(() => assertMaintainerThresholdsRemainSatisfiable(3, snapshot)).not.toThrow();
    expect(() => assertMaintainerThresholdsRemainSatisfiable(1, snapshot)).toThrow(/unsatisfied/);
  });

  it("normalizes template, binding, rule, and threshold order", () => {
    const first = policy();
    const reordered = GovernancePolicyRecordSchema.parse({
      ...first,
      policyTemplates: [...first.policyTemplates].reverse().map((template) => ({
        ...template,
        evidenceRules: [...template.evidenceRules].reverse(),
      })),
      decisionBindings: [...first.decisionBindings].reverse(),
    });
    const a = deriveGovernancePolicySnapshot(first);
    const b = deriveGovernancePolicySnapshot(reordered);
    expect(computeGovernancePolicySnapshotCommitment(a)).toBe(computeGovernancePolicySnapshotCommitment(b));
    expect(computeGovernancePolicySnapshotCommitment({ ...a, thresholds: [...a.thresholds].reverse() })).toBe(
      computeGovernancePolicySnapshotCommitment(a),
    );
  });

  it("changes commitment when any threshold or policy rule changes", () => {
    const first = deriveGovernancePolicySnapshot(policy());
    const higher = deriveGovernancePolicySnapshot(policy("v1", 3));
    const differentRule = deriveGovernancePolicySnapshot(GovernancePolicyRecordSchema.parse({
      ...policy(),
      decisionRules: ["unanimous maintainers"],
    }));
    expect(computeGovernancePolicySnapshotCommitment(higher)).not.toBe(computeGovernancePolicySnapshotCommitment(first));
    expect(computeGovernancePolicySnapshotCommitment(differentRule)).not.toBe(computeGovernancePolicySnapshotCommitment(first));
  });

  it("checks a supplied snapshot against the independently derived source policy", () => {
    const record = policy();
    const snapshot = deriveGovernancePolicySnapshot(record);
    expect(() => assertGovernancePolicySnapshotMatchesRecord(record, snapshot)).not.toThrow();
    expect(() => assertGovernancePolicySnapshotMatchesRecord(record, {
      ...snapshot,
      contentCommitment: "0x" + "b".repeat(64),
    })).toThrow(/does not match/);
    expect(() => assertGovernancePolicySnapshotMatchesRecord(policy("v1", 3), snapshot)).toThrow(/does not match/);
  });

  it("uses supersededAt to close a legacy record without effectiveUntil", () => {
    const record = GovernancePolicyRecordSchema.parse({
      ...policy(),
      effectiveUntil: undefined,
      supersededAt: "2026-11-05T00:00:00Z",
    });
    const previous = deriveGovernancePolicySnapshot(record);
    const next = {
      ...deriveGovernancePolicySnapshot(policy("v2", 3)),
      effectiveFrom: "2026-11-05T00:00:00Z",
      effectiveUntil: null,
    };
    expect(previous.effectiveUntil).toBe(record.supersededAt);
    expect(() => assertGovernancePolicyRevision(previous, next)).not.toThrow();
  });

  it("preserves a historically accepted zero-length effective window", () => {
    const record = GovernancePolicyRecordSchema.parse({
      ...policy(),
      effectiveUntil: "2026-10-05T00:00:00Z",
    });
    expect(() => deriveGovernancePolicySnapshot(record)).not.toThrow();
  });

  it("rejects sub-millisecond timestamps rather than colliding after Date normalization", () => {
    const snapshot = deriveGovernancePolicySnapshot(policy());
    for (const effectiveFrom of ["2026-10-05T00:00:00.0001Z", "2026-10-05T00:00:00.0002Z"]) {
      expect(() => GovernancePolicySnapshotSchema.parse({ ...snapshot, effectiveFrom })).toThrow();
    }
    expect(() => deriveGovernancePolicySnapshot(GovernancePolicyRecordSchema.parse({
      ...policy(),
      effectiveFrom: "2026-10-05T00:00:00.0001Z",
    }))).toThrow(/millisecond precision/);
  });

  it("reports legacy policy shapes that require migration to the V1 profile", () => {
    expect(() => deriveGovernancePolicySnapshot(policy("1.0.0"))).toThrow(/migrate to monotonic vN/);
    const incomplete = GovernancePolicyRecordSchema.parse({
      ...policy(),
      policyTemplates: policy().policyTemplates.slice(0, 2),
      decisionBindings: policy().decisionBindings.slice(0, 2),
    });
    expect(() => deriveGovernancePolicySnapshot(incomplete)).toThrow(/lacks V1 decision families/);
  });

  it("requires a new version and a closed previous effective window", () => {
    const previous = deriveGovernancePolicySnapshot(policy());
    const next = {
      ...deriveGovernancePolicySnapshot(policy("v2", 3)),
      effectiveFrom: "2026-11-05T00:00:00Z",
      effectiveUntil: null,
    };
    expect(() => assertGovernancePolicyRevision(previous, next)).not.toThrow();
    expect(() => assertGovernancePolicyRevision(previous, { ...next, policyVersion: "v1" })).toThrow(/increase/);
    expect(() => assertGovernancePolicyRevision(previous, { ...next, effectiveFrom: "2026-11-04T00:00:00Z" })).toThrow(/window/);
    expect(() => assertGovernancePolicyRevision({ ...previous, effectiveUntil: null }, next)).toThrow(/window/);
  });

  it("fails closed on missing families, duplicates, and the Compact five-signer ceiling", () => {
    const snapshot = deriveGovernancePolicySnapshot(policy());
    expect(() => GovernancePolicySnapshotSchema.parse({ ...snapshot, thresholds: snapshot.thresholds.slice(1) })).toThrow();
    expect(() => GovernancePolicySnapshotSchema.parse({
      ...snapshot,
      thresholds: [snapshot.thresholds[0], ...snapshot.thresholds],
    })).toThrow();
    expect(() => deriveGovernancePolicySnapshot(policy("v1", 6))).toThrow();
    expect(() => GovernancePolicySnapshotSchema.parse({ ...snapshot, extra: "ignored" })).toThrow();
    expect(() => GovernancePolicySnapshotSchema.parse({ ...snapshot, registryId: "Registry:Midnight:Kanon" })).toThrow();
    expect(() => GovernancePolicySnapshotSchema.parse({ ...snapshot, policyId: "Policy:Kanon" })).toThrow();
    expect(() => GovernancePolicySnapshotSchema.parse({
      ...snapshot,
      thresholds: snapshot.thresholds.map((entry) => entry.family === "member" ? { ...entry, threshold: 3 } : entry),
    })).toThrow(/Compact default threshold/);
    expect(() => GovernancePolicySnapshotSchema.parse({
      ...snapshot,
      thresholds: [...snapshot.thresholds, { family: "auditor", threshold: 3 }],
    })).toThrow(/Compact default threshold/);
  });
});
