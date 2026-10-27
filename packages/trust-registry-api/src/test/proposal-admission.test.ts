import {
  computeApplicationEvidenceCommitment,
  computeAuthorizationScopeCommitment,
  computeGovernancePolicySnapshotCommitment,
  computeIssuerStatusPolicyBindingCommitment,
  GovernancePolicySnapshotSchema,
  issuerGovernedResourceId,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
  TrustRegistryContract,
} from "@midnight-ntwrk/trust-registry-contract";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { describe, expect, it, vi } from "vitest";

import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";
import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import {
  assertProposalAdmission,
  ProposalAdmissionRejectedError,
  type AcceptedApplicationEvidence,
} from "../proposal-admission.js";
import { bindAcceptedLocalIssuerProposalTerms, prepareBoundLocalIssuerProposal } from "../local-issuer-proposal-terms.js";
import { createBoundLocalIssuerProposalPort } from "../local-issuer-proposal-port.js";
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
  statusDecisionCommitment: `0x${"4".repeat(64)}`,
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

const localPlan = {
  networkId: "undeployed",
  contractAddress: `0x${"7".repeat(64)}`,
  expectedGenesisHash: `0x${"8".repeat(64)}`,
} as const;
const currentPolicy = {
  registryId: binding.registryId,
  policyId: binding.policyId,
  version: binding.policyVersion,
} as const;
const localTerms = {
  format: "tr-local-issuer-proposal-terms-v1",
  ...localPlan,
  applicationId: binding.applicationId,
  authorizationId: pending.authorizationId,
  evidenceCommitment: evidence.commitment,
  trustLevel: "assessed",
  statusPolicyBinding: {
    version: "tr-issuer-status-policy-v1",
    trustRegistryId: binding.registryId,
    issuerAuthorizationId: pending.authorizationId,
    statusRegistryId: `0x${"5".repeat(64)}`,
    statusAuthorityVerificationMethod: "did:midnight:status:one#key-1",
    statusPolicyId: "status:policy:one",
    statusPolicyVersion: "v1",
    statusPolicyContentCommitment: `0x${"6".repeat(64)}`,
  },
} as const;

describe("local issuer proposal terms", () => {
  const bind = (overrides: Partial<Parameters<typeof bindAcceptedLocalIssuerProposalTerms>[0]> = {}) =>
    bindAcceptedLocalIssuerProposalTerms({
      terms: localTerms, pending, accepted, submittedEvidence: evidence,
      plan: localPlan, currentPolicy, ...overrides,
    });

  it("binds reviewer-visible terms to one accepted application and local deployment", () => {
    const result = bind();
    expect(result.reviewBindingSha256).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(result.statusPolicyBindingCommitment).toBe(
      computeIssuerStatusPolicyBindingCommitment(localTerms.statusPolicyBinding));
    expect(result.terms).toEqual(localTerms);
    expect(result.unsignedFields).toEqual({
      networkId: "undeployed",
      registryId: binding.registryId,
      contractAddress: localPlan.contractAddress,
      authorizationLabel: pending.authorizationId,
      authorizationId: bytes32Commitment(pending.authorizationId),
      subjectDidCommitment: bytes32Commitment(binding.subjectDid),
      resourceType: TrustRegistryContract.IssuerResourceType.credentialFamily,
      resourceId: bytes32Commitment(binding.governedResource.id),
      statusPolicyBindingCommitment: Buffer.from(result.statusPolicyBindingCommitment.slice(2), "hex"),
      trustLevel: bytes32Commitment(localTerms.trustLevel),
      evidenceHash: Buffer.from(evidence.commitment.slice(2), "hex"),
    });
    const differentlySigned = { ...evidence, signature: { ...evidence.signature, value: "alternate-signature" } };
    expect(bind({ submittedEvidence: differentlySigned, accepted: { ...accepted,
      evidence: differentlySigned } }).reviewBindingSha256).not.toBe(result.reviewBindingSha256);
  });

  it("rejects mixed evidence, deployment, status authority, and noncanonical terms", () => {
    for (const terms of [
      { ...localTerms, applicationId: "application:issuer:other" },
      { ...localTerms, evidenceCommitment: `0x${"9".repeat(64)}` },
      { ...localTerms, contractAddress: `0x${"9".repeat(64)}` },
      { ...localTerms, expectedGenesisHash: `0x${"9".repeat(64)}` },
      { ...localTerms, trustLevel: " assessed " },
      { ...localTerms, statusPolicyBinding: { ...localTerms.statusPolicyBinding,
        issuerAuthorizationId: "authorization:issuer:other" } },
    ]) expect(() => bind({ terms })).toThrow();
    expect(() => bind({ plan: { ...localPlan, networkId: "preview" as never } })).toThrow();
    expect(() => bind({ currentPolicy: { ...currentPolicy, registryId: "registry:other" } })).toThrow();
    expect(() => bind({ currentPolicy: { ...currentPolicy, policyId: "policy:other" } })).toThrow();
    expect(() => bind({ currentPolicy: { ...currentPolicy, version: "v2" } })).toThrow();
    expect(() => bind({ pending: { ...pending, status: "archived",
      archiveEventHash: `0x${"9".repeat(64)}` } })).toThrow();
    expect(() => bind({ accepted: { ...accepted, evidence: { ...evidence,
      signature: { ...evidence.signature, value: "substituted" } } } })).toThrow();
  });

  it("prepares a signable payload only for the selected policy and current verifier key", async () => {
    setNetworkId("undeployed");
    const policySnapshot = GovernancePolicySnapshotSchema.parse({
      format: "tr-policy-snapshot-v1",
      registryId: binding.registryId,
      policyId: binding.policyId,
      policyVersion: binding.policyVersion,
      effectiveFrom: "2026-10-13T00:00:00.000Z",
      effectiveUntil: null,
      contentCommitment: `0x${"a".repeat(64)}`,
      thresholds: ["maintainer", "member", "emergency", "archival"].map((family) => ({ family, threshold: 1 })),
    });
    const policyCommitment = Buffer.from(computeGovernancePolicySnapshotCommitment(policySnapshot).slice(2), "hex");
    const verifierAuthorizationId = bytes32Commitment("verifier:current");
    const verifierKeyId = bytes32Commitment("verifier-key:current");
    const maintainerKeyId = bytes32Commitment("maintainer-key:current");
    const maintainerSeed = new Uint8Array(32).fill(13);
    const verifierSeed = new Uint8Array(32).fill(19);
    const verifierDid = bytes32Commitment(binding.evidenceVerifierDid);
    const keyScope = TrustRegistryContract.pureCircuits.evidenceVerifierKeyScopeKey(verifierDid, policyCommitment);
    const suite = new Uint8Array(32);
    suite.set(new TextEncoder().encode("jubjub-schnorr"));
    const ledger = {
      initialized: true, contractVersion: 1n,
      registryId: bytes32Commitment(binding.registryId),
      deploymentNetworkIdCommitment: bytes32Commitment("undeployed"),
      governancePolicyCommitment: policyCommitment,
      governancePolicyVersion: 1n, governanceActionCount: 3n,
      maintainerThreshold: 1n, emergencyMaintainerThreshold: 1n, archivalMaintainerThreshold: 1n,
      maintainerKeyIds: { member: (id: Uint8Array) => Buffer.from(id).equals(maintainerKeyId) },
      maintainerRecords: { lookup: () => ({ keyId: maintainerKeyId,
        publicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed),
        status: TrustRegistryContract.MaintainerStatus.active }) },
      evidenceVerifierKeyRecords: {
        member: (id: Uint8Array) => Buffer.from(id).equals(verifierAuthorizationId),
        lookup: () => ({
          status: TrustRegistryContract.EvidenceVerifierKeyStatus.active,
          authorizationId: verifierAuthorizationId, keyIdCommitment: verifierKeyId,
          publicKey: deriveJubjubPublicKeyFromSeed(verifierSeed),
          verifierDidCommitment: verifierDid, policyCommitment, policyVersion: 1n, suite,
        }),
      },
      currentEvidenceVerifierKeyIdsByScopeKey: {
        member: (key: Uint8Array) => Buffer.from(key).equals(Buffer.from(keyScope)),
        lookup: () => verifierAuthorizationId,
      },
      issuerAuthorizationIds: { member: () => false },
      issuerProposalEvidenceRecords: { member: () => false },
      currentIssuerAuthorizationIdsByScopeKey: { member: () => false },
    } as unknown as TrustRegistryContract.Ledger;
    const prepare = (overrides: Partial<Parameters<typeof prepareBoundLocalIssuerProposal>[0]> = {}) =>
      prepareBoundLocalIssuerProposal({
        terms: localTerms, pending, accepted, submittedEvidence: evidence,
        plan: localPlan, policySnapshot, ledger, ...overrides,
      });
    const prepared = prepare();
    expect(prepared.signingContext.policyCommitment).toEqual(policyCommitment);
    expect(prepared.signingContext.evidenceVerifierAuthorizationId).toEqual(verifierAuthorizationId);
    expect(prepared.signingContext.actionSequence).toBe(3n);
    expect(prepared.signingReviewSha256).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(prepare({ ledger: { ...ledger, governanceActionCount: 4n } }).signingReviewSha256)
      .not.toBe(prepared.signingReviewSha256);
    expect(() => prepare({ policySnapshot: { ...policySnapshot,
      contentCommitment: `0x${"b".repeat(64)}` } })).toThrow(/selected policy snapshot/u);
    expect(() => prepare({ ledger: { ...ledger,
      currentEvidenceVerifierKeyIdsByScopeKey: {
        ...ledger.currentEvidenceVerifierKeyIdsByScopeKey, member: () => false,
      },
    } })).toThrow(/No current evidence-verifier key/u);

    const verifyLiveEvidence = vi.fn(async () => {});
    const readTrustedTimeMs = vi.fn(async () => Date.parse("2026-10-13T00:00:02.000Z"));
    const assertApprovedProviderCode = vi.fn(async () => {});
    const loadApprovedSubmissionProviders = vi.fn(async () => ({
      providers: {} as never, readSubmissionProviderIdentity: async () => ({
        contractAddress: localPlan.contractAddress, genesisHash: localPlan.expectedGenesisHash,
      }),
    }));
    const readAuthenticatedFinalizedSnapshot = vi.fn(async () => ({
      contractAddress: localPlan.contractAddress,
      genesisHash: localPlan.expectedGenesisHash,
      finalizedBlockHash: `0x${"a".repeat(64)}`,
      policySnapshot, ledger,
    }));
    const port = createBoundLocalIssuerProposalPort({
      plan: localPlan,
      async readCapturedAdmission(applicationId) {
        expect(applicationId).toBe(binding.applicationId);
        return { pending, accepted };
      },
      readAuthenticatedFinalizedSnapshot,
      readTrustedTimeMs,
      verifyLiveEvidence,
      assertApprovedProviderCode,
      loadApprovedSubmissionProviders,
    });
    const context = await port.prepare(pending.authorizationId, evidence, localTerms);
    expect(context).toEqual(prepared.signingContext);
    expect(verifyLiveEvidence).toHaveBeenCalledOnce();
    expect(assertApprovedProviderCode).not.toHaveBeenCalled();
    expect(loadApprovedSubmissionProviders).not.toHaveBeenCalled();
    await expect(port.prepare("issuer:wrong", evidence, localTerms))
      .rejects.toThrow(/authorization does not match/u);

    const signature = {} as Parameters<NonNullable<typeof port.preflightSubmission>>[3];
    await expect(port.preflightSubmission!(pending.authorizationId, evidence, [], signature,
      { ...context, actionSequence: 4n }, localTerms)).rejects.toThrow(/context is stale/u);
    expect(assertApprovedProviderCode).not.toHaveBeenCalled();
    expect(loadApprovedSubmissionProviders).not.toHaveBeenCalled();

    assertApprovedProviderCode.mockRejectedValueOnce(new Error("installed provider digest changed"));
    await expect(port.preflightSubmission!(pending.authorizationId, evidence, [], signature,
      context, localTerms)).rejects.toThrow(/installed provider digest changed/u);
    expect(loadApprovedSubmissionProviders).not.toHaveBeenCalled();

    readAuthenticatedFinalizedSnapshot.mockResolvedValueOnce({
      contractAddress: localPlan.contractAddress,
      genesisHash: `0x${"9".repeat(64)}`,
      finalizedBlockHash: `0x${"a".repeat(64)}`,
      policySnapshot, ledger,
    });
    await expect(port.prepare(pending.authorizationId, evidence, localTerms))
      .rejects.toThrow(/approved deployment/u);
    expect(verifyLiveEvidence).toHaveBeenCalledTimes(3);
    readAuthenticatedFinalizedSnapshot.mockResolvedValueOnce({
      contractAddress: localPlan.contractAddress,
      genesisHash: localPlan.expectedGenesisHash,
      finalizedBlockHash: `0x${"0".repeat(64)}`,
      policySnapshot, ledger,
    });
    await expect(port.prepare(pending.authorizationId, evidence, localTerms))
      .rejects.toThrow(/approved deployment/u);
    expect(verifyLiveEvidence).toHaveBeenCalledTimes(3);
    verifyLiveEvidence.mockRejectedValueOnce(new Error("live status authority unavailable"));
    await expect(port.prepare(pending.authorizationId, evidence, localTerms))
      .rejects.toThrow(/live status authority unavailable/u);
    expect(loadApprovedSubmissionProviders).not.toHaveBeenCalled();

    const verifierSignature = signIssuerProposalEvidenceFromSeed(
      verifierSeed, context.registryId, context.networkIdCommitment, context.contractAddress,
      context.evidenceVerifierKeyIdCommitment, context.actionPayloadHash,
    );
    const signers = [{ keyId: maintainerKeyId, publicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed),
      signature: signDeploymentBoundMaintainerActionFromSeed(
        maintainerSeed, context.registryId, context.networkIdCommitment, context.contractAddress,
        context.policyCommitment, context.actionKind, context.actionPayloadHash, context.actionSequence,
      ) }];
    await expect(port.preflightSubmission!(pending.authorizationId, evidence,
      signers, verifierSignature, context, localTerms)).resolves.toBeUndefined();
    expect(loadApprovedSubmissionProviders).toHaveBeenCalledOnce();
    expect(assertApprovedProviderCode).toHaveBeenCalledTimes(3);

    readTrustedTimeMs.mockResolvedValueOnce(Date.parse(evidence.envelope.expiresAt));
    await expect(port.preflightSubmission!(pending.authorizationId, evidence,
      signers, verifierSignature, context, localTerms)).rejects.toThrow(/not current at trusted time/u);
    expect(loadApprovedSubmissionProviders).toHaveBeenCalledOnce();
    readTrustedTimeMs.mockResolvedValueOnce(Number.NaN);
    await expect(port.execute(pending.authorizationId, evidence,
      signers, verifierSignature, localTerms)).rejects.toThrow(/not current at trusted time/u);
    expect(loadApprovedSubmissionProviders).toHaveBeenCalledOnce();

    readTrustedTimeMs.mockResolvedValueOnce(Date.parse("2026-10-13T00:00:02.000Z"));
    readTrustedTimeMs.mockResolvedValueOnce(Date.parse(evidence.envelope.expiresAt));
    await expect(port.execute(pending.authorizationId, evidence,
      signers, verifierSignature, localTerms)).rejects.toThrow(/not current at trusted time/u);
    expect(loadApprovedSubmissionProviders).toHaveBeenCalledTimes(2);
  });
});

describe("proposal admission", () => {
  it("prefers one captured admission pair over separately fetched revisions", async () => {
    const resolvePendingApplication = vi.fn(async () => { throw new Error("separate pending read must not run"); });
    const resolveAcceptedEvidence = vi.fn(async () => { throw new Error("separate accepted read must not run"); });
    const readCapturedAdmission = vi.fn(async (): Promise<{
      pending: PendingApplicationRecord | null;
      accepted: AcceptedApplicationEvidence | null;
    }> => ({ pending, accepted }));
    await expect(assertProposalAdmission({ resolvePendingApplication, resolveAcceptedEvidence,
      readCapturedAdmission }, "issuer", pending.authorizationId, evidence)).resolves.toBeUndefined();
    expect(readCapturedAdmission).toHaveBeenCalledExactlyOnceWith(binding.applicationId);
    expect(resolvePendingApplication).not.toHaveBeenCalled();
    expect(resolveAcceptedEvidence).not.toHaveBeenCalled();
    readCapturedAdmission.mockResolvedValueOnce({ pending: null, accepted });
    await expect(assertProposalAdmission({ resolvePendingApplication, resolveAcceptedEvidence,
      readCapturedAdmission }, "issuer", pending.authorizationId, evidence))
      .rejects.toBeInstanceOf(ProposalAdmissionRejectedError);
  });

  it("requires and forwards explicit issuer terms in local-ledger prepare", async () => {
    type Options = Parameters<typeof createTrustRegistryApiServer>[0];
    const source: Options["source"] = {
      mode: "local-ledger",
      localDeploymentBinding: {
        contractAddress: localPlan.contractAddress,
        expectedGenesisHash: localPlan.expectedGenesisHash,
      },
      async loadSnapshot() { throw new Error("unused"); },
      async readFinalizedProposalLedger() { throw new Error("unused"); },
    };
    const observed: unknown[] = [];
    const bytes = new Uint8Array(32).fill(1);
    const server = createTrustRegistryApiServer({
      source,
      governedIssuerProposals: {
        async prepare(_authorizationId, _evidence, terms) {
          observed.push(terms);
          return {
            registryId: bytes, networkIdCommitment: bytes, contractAddress: bytes,
            authorizationId: bytes, policyCommitment: bytes, policyVersion: 1n,
            actionKind: bytes, actionPayloadHash: bytes, actionSequence: 1n,
            evidenceHash: bytes, statusPolicyBindingCommitment: bytes,
            evidenceVerifierAuthorizationId: bytes, evidenceVerifierKeyIdCommitment: bytes,
          };
        },
        async preflightSubmission() {},
        async execute() { throw new Error("unused"); },
      },
      proposalAdmission: {
        async resolvePendingApplication() { return pending; },
        async resolveAcceptedEvidence() { return accepted; },
      },
      proposalSubmissionJournal: {
        async assertDeploymentBinding() {},
        async executeOnce() { throw new Error("unused"); },
        async reconcile() { throw new Error("unused"); },
      } as NonNullable<Options["proposalSubmissionJournal"]>,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Expected local HTTP listener");
      const url = `http://127.0.0.1:${address.port}/v1/governed/issuer/${pending.authorizationId}/proposal/prepare`;
      const post = (body: unknown) => fetch(url, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      expect((await post({ evidence })).status).toBe(400);
      expect(observed).toEqual([]);
      expect((await post({ evidence, terms: localTerms })).status).toBe(200);
      expect(observed).toEqual([localTerms]);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

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
