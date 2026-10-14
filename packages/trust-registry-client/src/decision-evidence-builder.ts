import {
  DecisionEvidenceSchema,
  TrustRegistryEvidenceBundleSchema,
  assertDecisionEvidenceInclusion,
  assertDecisionEvidenceMatchesAcceptedEpoch,
  assertDecisionEvidencePolicyCommitment,
  deriveGovernancePolicySnapshot,
  type AcceptedDecisionEpoch,
  type DecisionEvidence,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

export type DecisionEvidenceBuildInput = {
  bundle: TrustRegistryEvidenceBundle;
  acceptedEpoch: AcceptedDecisionEpoch;
  scope: unknown;
  didMethod: unknown;
  didStateBlockHash: string;
  publicationSignatures: DecisionEvidence["epoch"]["quorum"]["signatures"];
  governanceEvents: DecisionEvidence["governanceEvents"];
  decisionSequence: string;
};

/** Builds a claim; accepted-epoch and DID provenance remain the caller's responsibility. */
export function buildDecisionEvidenceClaim(input: DecisionEvidenceBuildInput): DecisionEvidence {
  const bundle = TrustRegistryEvidenceBundleSchema.parse(input.bundle);
  const grant = bundle.authorization;
  if (grant === undefined || (grant.role !== "issuer" && grant.role !== "verifier")) {
    throw new Error("Decision evidence requires an issuer or verifier authorization");
  }
  const accepted = input.acceptedEpoch;
  const common = {
    format: "tr-decision-evidence-v1",
    registry: {
      registryId: accepted.registryId,
      registryDid: accepted.registryDid,
      networkId: accepted.networkId,
      contractAddress: accepted.contractAddress,
    },
    anchorReferences: {
      registryEpoch: {
        networkId: accepted.networkId,
        contractAddress: accepted.contractAddress,
        transactionHash: accepted.transactionHash,
        blockHash: accepted.blockHash,
      },
      didState: { networkId: accepted.networkId, blockHash: input.didStateBlockHash },
    },
    epoch: {
      epochId: bundle.epoch.epochId,
      registryId: bundle.epoch.registryId,
      stateRoot: bundle.epoch.stateRoot,
      eventRoot: bundle.epoch.eventRoot,
      policyRoot: bundle.epoch.policyRoot,
      publicationPolicyCommitment: accepted.publicationPolicyCommitment,
      publicationSequence: accepted.publicationSequence,
      validFromSequence: accepted.validFromSequence,
      validUntilSequence: accepted.validUntilSequence,
      validFrom: bundle.epoch.validFrom,
      validUntil: bundle.epoch.validUntil,
      quorum: { requiredSignatures: accepted.requiredSignatures, signatures: input.publicationSignatures },
    },
    grant,
    policy: deriveGovernancePolicySnapshot(bundle.policy),
    inclusionProof: { ...bundle.inclusionProof, leafIndex: String(bundle.inclusionProof.leafIndex) },
    governanceEvents: input.governanceEvents,
    decisionSequence: input.decisionSequence,
  };
  const evidence = DecisionEvidenceSchema.parse(grant.role === "issuer"
    ? { ...common, role: "issuer", scope: input.scope, didMethod: input.didMethod,
        statusPolicyBinding: bundle.statusPolicyBinding }
    : { ...common, role: "verifier", scope: input.scope, didMethod: input.didMethod });
  assertDecisionEvidenceMatchesAcceptedEpoch(evidence, accepted);
  assertDecisionEvidenceInclusion(evidence);
  assertDecisionEvidencePolicyCommitment(evidence);
  return evidence;
}
