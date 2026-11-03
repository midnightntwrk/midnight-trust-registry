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
  resolveGovernedRecognitionAccreditorAnchor,
} from "../index.js";

const families = ["maintainer", "member", "emergency", "archival"] as const;
const recognitionScope = {
  registryId: "registry:midnight:kanon",
  recognizedRegistryId: "registry:external:partner",
  scopeResourceType: "credentialfamily",
  scopeResourceId: "credential-family:partner:v1",
};
const recognitionAnchor = {
  format: "tr-recognition-accreditor-anchor-v1" as const,
  targetRegistryId: recognitionScope.registryId,
  policyId: "policy:kanon",
  policyVersion: "v1",
  accreditorDid: "did:midnight:undeployed:accreditor",
  accreditorAssertionMethodId: "did:midnight:undeployed:accreditor#assertion-1",
  credentialFamilyId: "credential-family:registry-accreditation:v1",
  schemaId: "schema:registry-accreditation:v1",
  statusRegistryId: "status-registry:accreditation:v1",
  statusAuthorityDid: "did:midnight:undeployed:status",
  statusAuthorityMethodId: "did:midnight:undeployed:status#assertion-1",
  recognizedRegistryId: recognitionScope.recognizedRegistryId,
  scopeResourceType: recognitionScope.scopeResourceType,
  scopeResourceId: recognitionScope.scopeResourceId,
  effectiveFrom: "2026-10-05T00:00:00.000Z",
  effectiveUntil: "2026-10-06T00:00:00.000Z",
};

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

  it("binds exact accreditor anchors to the active governance policy commitment", () => {
    const record = GovernancePolicyRecordSchema.parse({
      ...policy(), recognitionAccreditorAnchors: [recognitionAnchor],
    });
    const activePolicyCommitment = computeGovernancePolicySnapshotCommitment(
      deriveGovernancePolicySnapshot(record),
    );
    const input = {
      policy: record,
      activePolicyCommitment,
      scope: recognitionScope,
      evaluatedAtMs: Date.parse("2026-10-05T12:00:00.000Z"),
    };
    const resolved = resolveGovernedRecognitionAccreditorAnchor(input);
    expect(resolved.anchor.accreditorDid).toBe(recognitionAnchor.accreditorDid);
    expect(resolved.commitment).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(() => resolveGovernedRecognitionAccreditorAnchor({
      ...input, policy: GovernancePolicyRecordSchema.parse({
        ...record, recognitionAccreditorAnchors: [{
          ...recognitionAnchor,
          accreditorDid: "did:midnight:undeployed:substituted",
          accreditorAssertionMethodId: "did:midnight:undeployed:substituted#assertion-1",
        }],
      }),
    })).toThrow(/active governed policy/u);
    expect(() => resolveGovernedRecognitionAccreditorAnchor({
      ...input, scope: { ...recognitionScope, scopeResourceId: "credential-family:other:v1" },
    })).toThrow(/exact scope/u);
    expect(() => resolveGovernedRecognitionAccreditorAnchor({
      ...input, evaluatedAtMs: Date.parse(recognitionAnchor.effectiveUntil),
    })).toThrow(/exact scope/u);
  });

  it("rejects duplicated, wrong-policy, and applicant-only recognition anchors", () => {
    expect(() => GovernancePolicyRecordSchema.parse({
      ...policy(), recognitionAccreditorAnchors: [recognitionAnchor, recognitionAnchor],
    })).toThrow(/distinct external registry/u);
    expect(() => GovernancePolicyRecordSchema.parse({
      ...policy(), recognitionAccreditorAnchors: [{ ...recognitionAnchor, policyVersion: "v2" }],
    })).toThrow(/this policy revision/u);
    const record = policy();
    expect(() => resolveGovernedRecognitionAccreditorAnchor({
      policy: record,
      activePolicyCommitment: computeGovernancePolicySnapshotCommitment(deriveGovernancePolicySnapshot(record)),
      scope: recognitionScope,
      evaluatedAtMs: Date.parse("2026-10-05T12:00:00.000Z"),
    })).toThrow(/exact scope/u);
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

  it("requires an explicit effectiveUntil for a superseded policy", () => {
    expect(() => GovernancePolicyRecordSchema.parse({
      ...policy(),
      effectiveUntil: undefined,
      supersededAt: "2026-11-05T00:00:00Z",
    })).toThrow(/explicit effectiveUntil/);
    const record = GovernancePolicyRecordSchema.parse({
      ...policy(),
      supersededAt: "2026-11-05T00:00:00Z",
    });
    expect(deriveGovernancePolicySnapshot(record).effectiveUntil).toBe(record.effectiveUntil);
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

  it("rejects invalid policy versions and incomplete decision families", () => {
    expect(() => policy("1.0.0")).toThrow();
    const incomplete = GovernancePolicyRecordSchema.parse({
      ...policy(),
      policyTemplates: policy().policyTemplates.slice(0, 2),
      decisionBindings: policy().decisionBindings.slice(0, 2),
    });
    expect(() => deriveGovernancePolicySnapshot(incomplete)).toThrow(/lacks V1 decision families/);
  });

  it("requires the next version and a non-overlapping effective window", () => {
    const previous = deriveGovernancePolicySnapshot(policy());
    const next = {
      ...deriveGovernancePolicySnapshot(policy("v2", 3)),
      effectiveFrom: "2026-11-05T00:00:00Z",
      effectiveUntil: null,
    };
    expect(() => assertGovernancePolicyRevision(previous, next)).not.toThrow();
    expect(() => assertGovernancePolicyRevision(previous, { ...next, policyVersion: "v1" })).toThrow(/increase/);
    expect(() => assertGovernancePolicyRevision(previous, { ...next, effectiveFrom: "2026-11-04T00:00:00Z" })).toThrow(/window/);
    expect(() => assertGovernancePolicyRevision({ ...previous, effectiveUntil: null }, next)).not.toThrow();
    expect(() => assertGovernancePolicyRevision({ ...previous, effectiveUntil: null }, {
      ...next,
      effectiveFrom: previous.effectiveFrom,
    })).toThrow(/window/);
    expect(() => assertGovernancePolicyRevision(previous, { ...next, policyVersion: "v3" })).toThrow(/by one/);
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
