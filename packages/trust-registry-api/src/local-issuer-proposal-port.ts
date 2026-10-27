import type { ApplicationEvidenceSubmission, GovernancePolicySnapshot } from "@midnight-ntwrk/trust-registry-domain";
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

export class LocalIssuerEvidenceTimeRejectedError extends Error {
  constructor() {
    super("Accepted issuer evidence is not current at trusted time");
    this.name = "LocalIssuerEvidenceTimeRejectedError";
  }
}

/** These dependencies must be implemented by a deployment-specific, independently reviewed adapter. */
export type LocalIssuerProposalPortDependencies = {
  plan: Pick<LocalLedgerRuntimePlan, "networkId" | "contractAddress" | "expectedGenesisHash"
    | "verifierKeySha256" | "maintenanceAuthority" | "sequenceTimestamps">;
  readCapturedAdmission: NonNullable<ProposalAdmissionPort["readCapturedAdmission"]>;
  /** Authenticate finality independently of the SDK submitting provider. */
  readAuthenticatedFinalizedSnapshot(contractAddress: string): Promise<FinalizedIssuerSnapshot>;
  /** Return trusted time for each prepare/preflight/execute, not the API host clock. */
  readTrustedTimeMs(): Promise<number>;
  /** Resolve DID, VP, VC status authority, and challenge from live local services at this trusted time. */
  verifyLiveEvidence(input: CapturedIssuerAdmission & {
    terms: LocalIssuerProposalTerms;
    submittedEvidence: ApplicationEvidenceSubmission;
    snapshot: FinalizedIssuerSnapshot;
    trustedTimeMs: number;
  }): Promise<void>;
  /** Recheck the immutable installed provider tree and exact-source digest before every SDK use. */
  assertApprovedProviderCode(): Promise<void>;
  loadApprovedSubmissionProviders(): Promise<SubmissionProviders>;
};

/**
 * Opt-in assembly only. The packaged signed-plan CLI does not construct this port;
 * injected finality, evidence, and provider implementations require separate review.
 */
export function createBoundLocalIssuerProposalPort(
  dependencies: LocalIssuerProposalPortDependencies,
): GovernedIssuerProposalPort {
  const readApprovedSnapshot = async (contractAddress: string): Promise<FinalizedIssuerSnapshot> => {
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
    if (!Number.isSafeInteger(trustedTimeMs)) {
      throw new Error("Trusted time source returned an invalid value");
    }
    if (trustedTimeMs < Date.parse(evidence.envelope.verifiedAt)
      || trustedTimeMs >= Date.parse(evidence.envelope.expiresAt)) {
      throw new LocalIssuerEvidenceTimeRejectedError();
    }
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
    await dependencies.verifyLiveEvidence({ terms, ...admission, submittedEvidence, snapshot, trustedTimeMs });
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
    await dependencies.assertApprovedProviderCode();
    const providers = await dependencies.loadApprovedSubmissionProviders();
    await dependencies.assertApprovedProviderCode();
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
        await dependencies.assertApprovedProviderCode();
        await assertEvidenceCurrent(evidence);
      });
    },
  };
}
