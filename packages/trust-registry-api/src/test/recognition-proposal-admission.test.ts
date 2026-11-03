import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnight-ntwrk/trust-registry-cli";
import {
  computeGovernancePolicySnapshotCommitment,
  deriveGovernancePolicySnapshot,
  GovernancePolicyRecordSchema,
  recognitionAccreditorAnchorCommitment,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import { afterEach, describe, expect, it } from "vitest";

import type { RecognitionAdmissionReceipt } from "../file-recognition-admission.js";
import {
  recognitionAuthorityChallengeBindingHash,
  recognitionAuthorityChallengeIdentityHash,
} from "../recognition-authority-challenges.js";
import { withRecognitionProposalAdmission } from "../recognition-proposal-admission.js";

const now = Date.parse("2026-10-05T12:00:00.000Z");
const binding = {
  targetRegistryId: "registry:midnight:reference",
  recognitionId: "recognition:partner:v1",
  authorityDid: "did:midnight:undeployed:partner",
  recognizedRegistryId: "registry:external:partner",
  scopeResourceType: "credentialfamily",
  scopeResourceId: "credential-family:partner:v1",
};
const anchor = {
  format: "tr-recognition-accreditor-anchor-v1" as const,
  targetRegistryId: binding.targetRegistryId,
  policyId: "policy:recognition",
  policyVersion: "v1",
  accreditorDid: "did:midnight:undeployed:accreditor",
  accreditorAssertionMethodId: "did:midnight:undeployed:accreditor#assertion-1",
  credentialFamilyId: "credential-family:registry-accreditation:v1",
  schemaId: "schema:registry-accreditation:v1",
  statusRegistryId: "status-registry:accreditation:v1",
  statusAuthorityDid: "did:midnight:undeployed:status",
  statusAuthorityMethodId: "did:midnight:undeployed:status#assertion-1",
  recognizedRegistryId: binding.recognizedRegistryId,
  scopeResourceType: binding.scopeResourceType,
  scopeResourceId: binding.scopeResourceId,
  effectiveFrom: "2026-10-05T00:00:00.000Z",
  effectiveUntil: "2026-10-06T00:00:00.000Z",
};
const policy = GovernancePolicyRecordSchema.parse({
  policyId: "policy:recognition",
  registryId: binding.targetRegistryId,
  version: "v1",
  policyUri: "https://registry.example/policy",
  status: "active",
  effectiveFrom: "2026-10-05T00:00:00.000Z",
  effectiveUntil: "2026-10-06T00:00:00.000Z",
  policyTemplates: (["maintainer", "member", "emergency", "archival"] as const).map((family) => ({
    templateId: `template:${family}`,
    family,
    name: `${family} governance`,
    description: `${family} decisions`,
    requiredMaintainerThreshold: 2,
    applicableRoles: ["maintainer"],
    applicableActionKinds: [`tr:${family}:authorize`],
    evidenceRules: ["quorum signatures", "verified accreditation"],
  })),
  decisionBindings: (["maintainer", "member", "emergency", "archival"] as const).map((family) => ({
    bindingId: `binding:${family}`,
    family,
    templateId: `template:${family}`,
    actionScopes: [`${family}-authorization`],
  })),
  decisionRules: ["majority maintainers"],
  disputeRules: ["appeal"],
  retentionRules: ["retain evidence commitments"],
  emergencyRules: ["suspend recognition"],
  lifecycleEventRoot: sha256Hex("recognition-events"),
  recognitionAccreditorAnchors: [anchor],
});
const policyCommitment = computeGovernancePolicySnapshotCommitment(deriveGovernancePolicySnapshot(policy));
const receipt: RecognitionAdmissionReceipt = {
  receiptId: sha256Hex("receipt"),
  recognitionId: binding.recognitionId,
  applicationHash: recognitionAuthorityChallengeIdentityHash(binding),
  challengeHash: sha256Hex("challenge"),
  bindingHash: recognitionAuthorityChallengeBindingHash(binding),
  policyCommitment,
  anchorCommitment: recognitionAccreditorAnchorCommitment(anchor),
  evidenceCommitment: sha256Hex("combined-verified-evidence"),
  acceptedAtMs: now - 1_000,
  expiresAtMs: now + 60_000,
};
const directories: string[] = [];
const fixture = async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-recognition-proposal-"));
  directories.push(directory);
  const governanceWorkspacePath = join(directory, "governance.json");
  let current = receipt;
  let governance = { governancePolicy: policy, activePolicyCommitment: policyCommitment };
  let executions = 0;
  const input = {
    recognitionId: binding.recognitionId,
    readBinding: async () => binding,
    receiptId: receipt.receiptId,
    evidenceCommitment: receipt.evidenceCommitment,
    governanceWorkspacePath,
    admissionStore: { readAccepted: async () => current },
    readCurrentGovernance: async () => governance,
    execute: async () => { executions += 1; return "proposed"; },
    clock: () => now,
  };
  return {
    input,
    setReceipt: (next: RecognitionAdmissionReceipt) => { current = next; },
    setGovernance: (next: typeof governance) => { governance = next; },
    executions: () => executions,
  };
};
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("recognition proposal admission", () => {
  it("executes only for current exact-scope accepted evidence under the governance lock", async () => {
    const { input } = await fixture();
    input.readBinding = async () => {
      await expect(withExclusiveWorkspaceWrite(input.governanceWorkspacePath, async () => "mutated"))
        .rejects.toBeInstanceOf(WorkspaceMutationLockedError);
      return binding;
    };
    input.execute = async () => {
      await expect(withExclusiveWorkspaceWrite(input.governanceWorkspacePath, async () => "mutated"))
        .rejects.toBeInstanceOf(WorkspaceMutationLockedError);
      return "proposed";
    };
    await expect(withRecognitionProposalAdmission(input)).resolves.toBe("proposed");
  });

  it("rejects wrong receipt, scope, evidence, and expired admission before proposal execution", async () => {
    const f = await fixture();
    const wrong = [
      { ...f.input, receiptId: sha256Hex("other-receipt") },
      { ...f.input, evidenceCommitment: sha256Hex("other-evidence") },
      { ...f.input, readBinding: async () => ({ ...binding, authorityDid: "did:midnight:undeployed:other" }) },
      { ...f.input, readBinding: async () => ({ ...binding, scopeResourceId: "credential-family:other:v1" }) },
      { ...f.input, recognitionId: "recognition:other:v1" },
      { ...f.input, clock: () => receipt.expiresAtMs },
    ];
    for (const input of wrong) await expect(withRecognitionProposalAdmission(input)).rejects.toThrow();
    expect(f.executions()).toBe(0);
  });

  it("rejects an anchor change or an inactive policy after receipt acceptance", async () => {
    const f = await fixture();
    const changedAnchor = { ...anchor, accreditorDid: "did:midnight:undeployed:replacement",
      accreditorAssertionMethodId: "did:midnight:undeployed:replacement#assertion-1" };
    const changedPolicy = GovernancePolicyRecordSchema.parse({ ...policy, recognitionAccreditorAnchors: [changedAnchor] });
    f.setGovernance({ governancePolicy: changedPolicy,
      activePolicyCommitment: computeGovernancePolicySnapshotCommitment(deriveGovernancePolicySnapshot(changedPolicy)) });
    await expect(withRecognitionProposalAdmission(f.input)).rejects.toThrow(/stale/u);
    f.setGovernance({ governancePolicy: GovernancePolicyRecordSchema.parse({ ...policy, status: "proposed" }),
      activePolicyCommitment: policyCommitment });
    await expect(withRecognitionProposalAdmission(f.input)).rejects.toThrow(/active governed policy/u);
    expect(f.executions()).toBe(0);
  });

  it("refuses a substituted persisted receipt even with the same recognition ID", async () => {
    const f = await fixture();
    f.setReceipt({ ...receipt, bindingHash: sha256Hex("substituted-binding") });
    await expect(withRecognitionProposalAdmission(f.input)).rejects.toThrow(/does not match/u);
    expect(f.executions()).toBe(0);
  });
});
