import {
  computeApplicationEvidenceCommitment,
  computeAuthorizationScopeCommitment,
  issuerGovernedResourceId,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";
import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import {
  assertProposalAdmission,
  ProposalAdmissionRejectedError,
  type AcceptedApplicationForProposal,
} from "../proposal-admission.js";

const scope = {
  version: "tr-scope-v1",
  role: "issuer",
  credentialFamilyId: "credential-family:company",
  schemaId: "schema:company",
  schemaVersion: "1.0.0",
  credentialDefinitionId: "credential-definition:company",
  statusMethod: "midnight-status-registry-v1",
} as const;
const binding: ApplicationChallengeBinding = {
  registryId: "registry:trusted:one",
  applicationId: "application:issuer:one",
  subjectDid: "did:midnight:issuer:one",
  evidenceVerifierDid: "did:midnight:verifier:one",
  role: "issuer",
  policyId: "policy:trusted:v1",
  policyVersion: "v1",
  scope,
  scopeCommitment: computeAuthorizationScopeCommitment(scope),
  governedResource: { type: "credentialFamily", id: issuerGovernedResourceId(scope, "credentialFamily") },
};
const envelope = {
  version: "tr-application-evidence-v1",
  registryId: binding.registryId,
  applicationId: binding.applicationId,
  subjectDid: binding.subjectDid,
  role: binding.role,
  policyId: binding.policyId,
  policyVersion: binding.policyVersion,
  scopeCommitment: binding.scopeCommitment,
  governedResource: binding.governedResource,
  evidenceVerifierDid: binding.evidenceVerifierDid,
  verifiedAt: "2026-10-13T00:00:00.000Z",
  expiresAt: "2026-10-13T00:05:00.000Z",
  challengeHash: `0x${"1".repeat(64)}`,
  presentationHash: `0x${"2".repeat(64)}`,
  claimsCommitment: `0x${"3".repeat(64)}`,
} as const;
const evidence: ApplicationEvidenceSubmission = {
  envelope,
  commitment: computeApplicationEvidenceCommitment(envelope),
  signature: { keyId: `${binding.evidenceVerifierDid}#key-1`, algorithm: "jubjub-schnorr", value: "signed" },
};
const accepted: AcceptedApplicationForProposal = {
  authorizationId: "authorization:issuer:one",
  binding,
  evidence,
  receipt: {
    receiptId: `0x${"4".repeat(64)}`,
    evidenceCommitment: evidence.commitment,
    acceptedAt: "2026-10-13T00:00:01.000Z",
  },
};

describe("proposal admission", () => {
  it("refuses a combined VP and proposal server without a receipt-backed admission port", () => {
    expect(() => createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "proposal-admission" }).snapshot),
      applicationVp: {
        challengeStore: new InMemoryApplicationChallengeStore(),
        authorizeRequest: async () => {},
        resolvePendingApplication: async () => null,
        verifyPresentation: async () => { throw new Error("unused"); },
        signEvidence: async () => evidence.signature,
        verifyEvidenceSignature: () => false,
        persistRedactedEvidence: async () => accepted.receipt,
      },
      governedIssuerProposals: {
        prepare: async () => { throw new Error("unused"); },
        execute: async () => { throw new Error("unused"); },
      },
    })).toThrow(/accepted-application admission port/u);
  });

  it("requires the exact accepted VP receipt, role, target, binding and redacted evidence", async () => {
    let current: AcceptedApplicationForProposal | null = accepted;
    const port = { resolveAcceptedApplication: async () => current };
    await expect(assertProposalAdmission(port, "issuer", accepted.authorizationId, evidence)).resolves.toBeUndefined();

    const rejected = async (role: "issuer" | "verifier", target: string, submitted = evidence) =>
      expect(assertProposalAdmission(port, role, target, submitted)).rejects.toBeInstanceOf(ProposalAdmissionRejectedError);
    current = null;
    await rejected("issuer", accepted.authorizationId);
    current = accepted;
    await rejected("verifier", accepted.authorizationId);
    await rejected("issuer", "authorization:issuer:other");
    await rejected("issuer", accepted.authorizationId, {
      ...evidence, signature: { ...evidence.signature, value: "substituted" },
    });
    await rejected("issuer", accepted.authorizationId, {
      ...evidence, envelope: { ...evidence.envelope, challengeHash: `0x${"5".repeat(64)}` },
    });

    for (const changed of [
      { ...accepted, binding: { ...binding, policyVersion: "v2" } },
      { ...accepted, binding: { ...binding, governedResource: { ...binding.governedResource, id: "wrong" } } },
      { ...accepted, receipt: { ...accepted.receipt, evidenceCommitment: `0x${"5".repeat(64)}` } },
      { ...accepted, evidence: { ...evidence, commitment: `0x${"5".repeat(64)}` } },
    ]) {
      current = changed;
      await rejected("issuer", accepted.authorizationId);
    }
  });
});
