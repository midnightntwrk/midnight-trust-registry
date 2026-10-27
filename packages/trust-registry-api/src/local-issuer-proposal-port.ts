import type { ApplicationEvidenceSubmission, GovernancePolicySnapshot } from "@midnight-ntwrk/trust-registry-domain";
import type { TrustRegistryJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { TrustRegistryContract } from "@midnight-ntwrk/trust-registry-contract";
import {
  executeLocalIssuerProposalAfterReservation,
  preflightLocalIssuerProposalSubmission,
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
import type { LocalLedgerRuntimePlan } from "./local-ledger-runtime.js";
import {
  LocalIssuerProposalTermsSchema,
  prepareBoundLocalIssuerProposal,
  type LocalIssuerProposalTerms,
} from "./local-issuer-proposal-terms.js";
import type { AcceptedApplicationEvidence } from "./proposal-admission.js";
import type { PendingApplicationRecord } from "./pending-application-registration.js";

type FinalizedIssuerSnapshot = {
  contractAddress: string;
  genesisHash: string;
  policySnapshot: GovernancePolicySnapshot;
  ledger: TrustRegistryContract.Ledger;
};

type CapturedIssuerAdmission = {
  pending: PendingApplicationRecord | null;
  accepted: AcceptedApplicationEvidence | null;
};

type SubmissionProviders = Pick<LocalIssuerProposalSubmissionInput,
  "providers" | "readSubmissionProviderIdentity">;

/** These dependencies must be implemented by a deployment-specific, independently reviewed adapter. */
export type LocalIssuerProposalPortDependencies = {
  plan: Pick<LocalLedgerRuntimePlan, "networkId" | "contractAddress" | "expectedGenesisHash">;
  readCapturedAdmission(applicationId: string): Promise<CapturedIssuerAdmission>;
  /** Authenticate finality independently of the SDK submitting provider. */
  readAuthenticatedFinalizedSnapshot(contractAddress: string): Promise<FinalizedIssuerSnapshot>;
  /** Resolve DID, VP, VC status authority, challenge, and trusted time from live local services. */
  verifyLiveEvidence(input: CapturedIssuerAdmission & {
    terms: LocalIssuerProposalTerms;
    submittedEvidence: ApplicationEvidenceSubmission;
    snapshot: FinalizedIssuerSnapshot;
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
    const snapshot = await dependencies.readAuthenticatedFinalizedSnapshot(dependencies.plan.contractAddress);
    if (snapshot.contractAddress !== dependencies.plan.contractAddress
      || snapshot.genesisHash !== dependencies.plan.expectedGenesisHash) {
      throw new Error("Authenticated issuer ledger does not match the approved deployment");
    }
    const prepared = prepareBoundLocalIssuerProposal({
      terms, ...admission, submittedEvidence, plan: dependencies.plan,
      policySnapshot: snapshot.policySnapshot, ledger: snapshot.ledger,
    });
    await dependencies.verifyLiveEvidence({ terms, ...admission, submittedEvidence, snapshot });
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
          const snapshot = await dependencies.readAuthenticatedFinalizedSnapshot(contractAddress);
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
      const { input } = await submissionInput(authorizationId, evidence, signers, signature, terms);
      return executeLocalIssuerProposalAfterReservation(input);
    },
  };
}
