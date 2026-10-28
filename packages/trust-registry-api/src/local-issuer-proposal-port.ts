import {
  compareRfc3339Instants,
  computeIssuerStatusPolicyBindingCommitment,
  type ApplicationEvidenceSubmission,
  type GovernancePolicySnapshot,
} from "@midnight-ntwrk/trust-registry-domain";
import type { TrustRegistryJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import {
  executeLocalIssuerProposalAfterReservation,
  preflightLocalIssuerProposalSubmission,
  type FinalizedRegistryLedgerView,
  type LocalIssuerProposalCall,
  type LocalIssuerProposalSubmissionInput,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  sameGovernedIssuerProposal,
  serializeGovernedIssuerProposal,
  type GovernedIssuerProposalContext,
  type GovernedIssuerProposalPort,
} from "./governed-issuer-proposals.js";
import type { GovernedMembershipSigner } from "./governed-membership-actions.js";
import {
  assertApprovedDeploymentImage,
  assertApprovedPlanCoversGovernanceCount,
  type LocalLedgerRuntimePlan,
} from "./local-ledger-runtime.js";
import {
  LocalIssuerProposalTermsSchema,
  prepareBoundLocalIssuerProposal,
  type LocalIssuerProposalTerms,
} from "./local-issuer-proposal-terms.js";
import {
  validateLocalIssuerWriterApproval,
  type LocalIssuerWriterApproval,
} from "./local-issuer-writer-approval.js";
import type { ProposalAdmissionPort } from "./proposal-admission.js";

export type FinalizedIssuerSnapshot = Pick<FinalizedRegistryLedgerView,
  "networkId" | "contractAddress" | "verifierKeySha256" | "maintenanceAuthority" | "ledger"> & {
  genesisHash: string;
  finalizedBlockHash: string;
  policySnapshot: GovernancePolicySnapshot;
};

type CapturedIssuerAdmission = Awaited<ReturnType<NonNullable<ProposalAdmissionPort["readCapturedAdmission"]>>>;

type SubmissionProviders = Pick<LocalIssuerProposalSubmissionInput,
  "providers" | "readSubmissionProviderIdentity">;

type InstalledProviderVerification = {
  format: "tr-installed-provider-runtime-verification-v1";
  sourceRevision: string;
  installInventorySha256: string;
  contentSha256: string;
  ownership: "trusted-tree-check-passed";
  releaseQualified: false;
};

export type LiveIssuerEvidenceVerification = {
  format: "tr-live-issuer-evidence-verification-v1";
  sourceRevision: string;
  networkId: string;
  contractAddress: string;
  finalizedBlockHash: string;
  applicationId: string;
  evidenceCommitment: string;
  statusPolicyBindingCommitment: string;
  statusRegistryId: string;
  statusAuthorityVerificationMethod: string;
  trustedTimeMs: number;
};

export class LocalIssuerEvidenceTimeRejectedError extends Error {
  constructor() {
    super("Accepted issuer evidence is not current at trusted time");
    this.name = "LocalIssuerEvidenceTimeRejectedError";
  }
}

export function assertIssuerEvidenceCurrentAtTrustedTime(
  envelope: Pick<ApplicationEvidenceSubmission["envelope"], "verifiedAt" | "expiresAt">,
  trustedTimeMs: number,
): void {
  const trustedDate = new Date(trustedTimeMs);
  if (!Number.isSafeInteger(trustedTimeMs) || !Number.isFinite(trustedDate.getTime())) {
    throw new Error("Trusted time source returned an invalid value");
  }
  const trustedTime = trustedDate.toISOString();
  if (compareRfc3339Instants(trustedTime, envelope.verifiedAt) < 0
    || compareRfc3339Instants(trustedTime, envelope.expiresAt) >= 0) {
    throw new LocalIssuerEvidenceTimeRejectedError();
  }
}

/** These dependencies must be implemented by a deployment-specific, independently reviewed adapter. */
export type LocalIssuerProposalPortDependencies = {
  plan: Pick<LocalLedgerRuntimePlan, "networkId" | "contractAddress" | "expectedGenesisHash"
    | "verifierKeySha256" | "maintenanceAuthority" | "sequenceTimestamps"
    | "sourceRevision" | "installInventorySha256" | "notBefore" | "notAfter">;
  /** Digest returned by verified loading of the exact signed API plan bytes. */
  approvedPlanSha256: string;
  /** Reviewer identity returned by verification of that same signed API plan. */
  approvedPlanReviewerFingerprint: string;
  /** Must be loaded from a separate, detached-signed writer approval. */
  writerApproval: LocalIssuerWriterApproval;
  /** The host must initialize the API-owned journal at this approved path. */
  submissionJournalPath: string;
  readCapturedAdmission: NonNullable<ProposalAdmissionPort["readCapturedAdmission"]>;
  /** Authenticate finality independently of the SDK submitting provider. */
  readAuthenticatedFinalizedSnapshot(contractAddress: string): Promise<FinalizedIssuerSnapshot>;
  /** Return trusted time for each prepare/preflight/execute, not the API host clock. */
  readTrustedTimeMs(): Promise<number>;
  /** Independently resolve DID, VP, VC status authority, and challenge from live local services. The returned binding is not itself proof of that verification. */
  verifyLiveEvidence(input: CapturedIssuerAdmission & {
    terms: LocalIssuerProposalTerms;
    submittedEvidence: ApplicationEvidenceSubmission;
    snapshot: FinalizedIssuerSnapshot;
    trustedTimeMs: number;
  }): Promise<LiveIssuerEvidenceVerification>;
  /** Recheck the immutable installed provider tree and exact-source digest before every SDK use. */
  assertApprovedProviderCode(): Promise<InstalledProviderVerification>;
  loadApprovedSubmissionProviders(): Promise<SubmissionProviders>;
};

/**
 * Opt-in assembly only. The packaged signed-plan CLI does not construct this port;
 * injected finality, evidence, and provider implementations require separate review.
 */
export function createBoundLocalIssuerProposalPort(
  dependencies: LocalIssuerProposalPortDependencies,
): GovernedIssuerProposalPort {
  const approval = validateLocalIssuerWriterApproval(dependencies.writerApproval, {
    plan: dependencies.plan, planSha256: dependencies.approvedPlanSha256,
    approvedPlanReviewerFingerprint: dependencies.approvedPlanReviewerFingerprint,
  });
  const assertWriterApprovalCurrent = (): void => {
    validateLocalIssuerWriterApproval(approval, {
      plan: dependencies.plan, planSha256: dependencies.approvedPlanSha256,
      approvedPlanReviewerFingerprint: dependencies.approvedPlanReviewerFingerprint,
    });
  };
  if (dependencies.submissionJournalPath !== approval.submissionJournalPath) {
    throw new Error("Issuer journal path differs from the signed writer approval");
  }
  const assertProviderIdentity = async (): Promise<void> => {
    assertWriterApprovalCurrent();
    const verified = await dependencies.assertApprovedProviderCode();
    if (verified?.format !== "tr-installed-provider-runtime-verification-v1"
      || verified.sourceRevision !== dependencies.plan.sourceRevision
      || verified.installInventorySha256 !== dependencies.plan.installInventorySha256
      || verified.contentSha256 !== approval.providerContentSha256
      || verified.ownership !== "trusted-tree-check-passed"
      || verified.releaseQualified !== false) {
      throw new Error("Installed issuer provider identity differs from the reviewed plan and content pin");
    }
  };
  const readApprovedSnapshot = async (contractAddress: string): Promise<FinalizedIssuerSnapshot> => {
    assertWriterApprovalCurrent();
    if (contractAddress !== dependencies.plan.contractAddress) {
      throw new Error("Issuer snapshot request differs from the approved contract");
    }
    const snapshot = await dependencies.readAuthenticatedFinalizedSnapshot(contractAddress);
    if (snapshot.contractAddress !== dependencies.plan.contractAddress
      || snapshot.genesisHash !== dependencies.plan.expectedGenesisHash
      || !/^0x[0-9a-f]{64}$/u.test(snapshot.finalizedBlockHash)
      || /^0x0{64}$/u.test(snapshot.finalizedBlockHash)) {
      throw new Error("Authenticated issuer ledger does not match the approved deployment");
    }
    assertApprovedDeploymentImage(dependencies.plan, snapshot);
    assertApprovedPlanCoversGovernanceCount(dependencies.plan, snapshot.ledger.governanceActionCount);
    return snapshot;
  };

  const assertEvidenceCurrent = async (evidence: ApplicationEvidenceSubmission): Promise<number> => {
    const trustedTimeMs = await dependencies.readTrustedTimeMs();
    assertIssuerEvidenceCurrentAtTrustedTime(evidence.envelope, trustedTimeMs);
    return trustedTimeMs;
  };

  const loadPrepared = async (
    authorizationId: string,
    submittedEvidence: ApplicationEvidenceSubmission,
    inputTerms: LocalIssuerProposalTerms | undefined,
  ) => {
    const terms = LocalIssuerProposalTermsSchema.parse(inputTerms);
    if (terms.authorizationId !== authorizationId) {
      throw new Error("Issuer proposal authorization does not match reviewed terms");
    }
    const admission = await dependencies.readCapturedAdmission(terms.applicationId);
    const snapshot = await readApprovedSnapshot(dependencies.plan.contractAddress);
    const prepared = prepareBoundLocalIssuerProposal({
      terms, ...admission, submittedEvidence, plan: dependencies.plan,
      policySnapshot: snapshot.policySnapshot, ledger: snapshot.ledger,
    });
    const trustedTimeMs = await assertEvidenceCurrent(submittedEvidence);
    const verified = await dependencies.verifyLiveEvidence({ terms, ...admission, submittedEvidence, snapshot, trustedTimeMs });
    if (verified?.format !== "tr-live-issuer-evidence-verification-v1"
      || verified.sourceRevision !== dependencies.plan.sourceRevision
      || verified.networkId !== dependencies.plan.networkId
      || verified.contractAddress !== dependencies.plan.contractAddress
      || verified.finalizedBlockHash !== snapshot.finalizedBlockHash
      || verified.applicationId !== terms.applicationId
      || verified.evidenceCommitment !== submittedEvidence.commitment
      || verified.statusPolicyBindingCommitment !== computeIssuerStatusPolicyBindingCommitment(terms.statusPolicyBinding)
      || verified.statusRegistryId !== terms.statusPolicyBinding.statusRegistryId
      || verified.statusAuthorityVerificationMethod !== terms.statusPolicyBinding.statusAuthorityVerificationMethod
      || verified.trustedTimeMs !== trustedTimeMs) {
      throw new Error("Live issuer evidence result differs from the approved deployment, evidence, or status policy");
    }
    return prepared;
  };

  const submissionInput = async (
    authorizationId: string,
    evidence: ApplicationEvidenceSubmission,
    signers: readonly GovernedMembershipSigner[],
    evidenceVerifierSignature: TrustRegistryJubjubSignature,
    terms: LocalIssuerProposalTerms | undefined,
    expectedContext?: GovernedIssuerProposalContext,
  ): Promise<{ prepared: Awaited<ReturnType<typeof loadPrepared>>; input: LocalIssuerProposalSubmissionInput }> => {
    const prepared = await loadPrepared(authorizationId, evidence, terms);
    if (expectedContext !== undefined && !sameGovernedIssuerProposal(
      serializeGovernedIssuerProposal(prepared.signingContext),
      serializeGovernedIssuerProposal(expectedContext),
    )) throw new Error("Issuer proposal signing context is stale");
    const call: LocalIssuerProposalCall = {
      ...prepared.unsignedFields,
      policyId: prepared.signingContext.policyCommitment,
      evidenceVerifierAuthorizationId: prepared.signingContext.evidenceVerifierAuthorizationId,
      evidenceVerifierKeyIdCommitment: prepared.signingContext.evidenceVerifierKeyIdCommitment,
      evidenceVerifierSignature,
      signers,
    };
    await assertProviderIdentity();
    const providers = await dependencies.loadApprovedSubmissionProviders();
    await assertProviderIdentity();
    return {
      prepared,
      input: {
        call, expectedGenesisHash: dependencies.plan.expectedGenesisHash, ...providers,
        readFinalizedLedger: async (contractAddress) => {
          const snapshot = await readApprovedSnapshot(contractAddress);
          return { contractAddress: snapshot.contractAddress, genesisHash: snapshot.genesisHash, ledger: snapshot.ledger };
        },
      },
    };
  };

  return {
    async prepare(authorizationId, evidence, terms) {
      return (await loadPrepared(authorizationId, evidence, terms)).signingContext;
    },
    async preflightSubmission(authorizationId, evidence, signers, signature, context, terms) {
      const { input } = await submissionInput(authorizationId, evidence, signers, signature, terms, context);
      await preflightLocalIssuerProposalSubmission(input);
    },
    async execute(authorizationId, evidence, signers, signature, terms) {
      const { prepared, input } = await submissionInput(authorizationId, evidence, signers, signature, terms);
      return executeLocalIssuerProposalAfterReservation(input, async () => {
        const current = await loadPrepared(authorizationId, evidence, terms);
        if (!sameGovernedIssuerProposal(
          serializeGovernedIssuerProposal(prepared.signingContext),
          serializeGovernedIssuerProposal(current.signingContext),
        )) throw new Error("Issuer proposal signing context changed before broadcast");
        await assertProviderIdentity();
        await assertEvidenceCurrent(evidence);
        assertWriterApprovalCurrent();
      });
    },
  };
}
