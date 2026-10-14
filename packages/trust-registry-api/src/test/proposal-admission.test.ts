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
  type AcceptedApplicationEvidence,
} from "../proposal-admission.js";
import type { PendingApplicationRecord } from "../pending-application-registration.js";

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
const pending: PendingApplicationRecord = {
  authorizationId: "authorization:issuer:one",
  binding,
  status: "pending",
  createdAt: "2026-10-13T00:00:00.000Z",
};
const accepted: AcceptedApplicationEvidence = {
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
    let currentPending: PendingApplicationRecord | null = pending;
    let currentAccepted: AcceptedApplicationEvidence | null = accepted;
    const port = {
      resolvePendingApplication: async () => currentPending,
      resolveAcceptedEvidence: async () => currentAccepted,
    };
    const authorizationId = pending.authorizationId;
    await expect(assertProposalAdmission(port, "issuer", authorizationId, evidence)).resolves.toBeUndefined();

    const rejected = async (role: "issuer" | "verifier", target: string, submitted = evidence) =>
      expect(assertProposalAdmission(port, role, target, submitted)).rejects.toBeInstanceOf(ProposalAdmissionRejectedError);
    currentPending = null;
    await rejected("issuer", authorizationId);
    currentPending = pending;
    currentAccepted = null;
    await rejected("issuer", authorizationId);
    currentAccepted = accepted;
    await rejected("verifier", authorizationId);
    await rejected("issuer", "authorization:issuer:other");
    await rejected("issuer", authorizationId, {
      ...evidence, signature: { ...evidence.signature, value: "substituted" },
    });
    await rejected("issuer", authorizationId, {
      ...evidence, envelope: { ...evidence.envelope, challengeHash: `0x${"5".repeat(64)}` },
    });

    for (const changed of [
      { ...pending, authorizationId: "authorization:issuer:substituted" },
      { ...pending, binding: { ...binding, policyVersion: "v2" } },
      { ...pending, binding: { ...binding, governedResource: { ...binding.governedResource, id: "wrong" } } },
    ]) {
      currentPending = changed;
      await rejected("issuer", authorizationId);
    }
    currentPending = pending;
    for (const changed of [
      { ...accepted, receipt: { ...accepted.receipt, evidenceCommitment: `0x${"5".repeat(64)}` } },
      { ...accepted, evidence: { ...evidence, commitment: `0x${"5".repeat(64)}` } },
    ]) {
      currentAccepted = changed;
      await rejected("issuer", authorizationId);
    }
  });
});
