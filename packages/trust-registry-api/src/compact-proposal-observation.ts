import { Buffer } from "node:buffer";

import {
  TrustRegistryContract,
  computeAuditorEvidenceBoundProposalPayloadHash,
  computeCreateAuditorAuthorizationPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateMaintainerMembershipPayloadHash,
  computeCreateRecognitionPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  computeRecognitionEvidenceBoundProposalPayloadHash,
  computeVerifierEvidenceBoundProposalPayloadHash,
  verifyAuditorProposalEvidenceSignature,
  verifyIssuerProposalEvidenceSignature,
  verifyMaintainerProposalEvidenceSignature,
  verifyRecognitionProposalEvidenceSignature,
  verifyVerifierProposalEvidenceSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

import {
  GovernedProposalObservationSchema,
  type GovernedProposalObservation,
} from "./governed-proposal-observation.js";

type Ledger = ReturnType<typeof TrustRegistryContract.ledger>;
export type ProposalRole = "issuer" | "verifier" | "auditor" | "maintainer" | "recognition";

const proposalRecordKeys = {
  issuer: "issuerProposalEvidenceRecords",
  verifier: "verifierProposalEvidenceRecords",
  auditor: "auditorProposalEvidenceRecords",
  maintainer: "maintainerProposalEvidenceRecords",
  recognition: "recognitionProposalEvidenceRecords",
} as const satisfies Record<ProposalRole, keyof Ledger>;

const authorizationRecordKeys = {
  issuer: "issuerAuthorizationRecords",
  verifier: "verifierAuthorizationRecords",
  auditor: "auditorAuthorizationRecords",
  maintainer: "maintainerMembershipRecords",
  recognition: "recognitionRecords",
} as const satisfies Record<ProposalRole, keyof Ledger>;

const proposalEvidenceOperations = {
  issuer: {
    bind: computeIssuerEvidenceBoundProposalPayloadHash,
    verify: verifyIssuerProposalEvidenceSignature,
  },
  verifier: {
    bind: computeVerifierEvidenceBoundProposalPayloadHash,
    verify: verifyVerifierProposalEvidenceSignature,
  },
  auditor: {
    bind: computeAuditorEvidenceBoundProposalPayloadHash,
    verify: verifyAuditorProposalEvidenceSignature,
  },
  maintainer: {
    bind: computeMaintainerEvidenceBoundProposalPayloadHash,
    verify: verifyMaintainerProposalEvidenceSignature,
  },
  recognition: {
    bind: computeRecognitionEvidenceBoundProposalPayloadHash,
    verify: verifyRecognitionProposalEvidenceSignature,
  },
} as const satisfies Record<ProposalRole, {
  bind: typeof computeIssuerEvidenceBoundProposalPayloadHash;
  verify: typeof verifyIssuerProposalEvidenceSignature;
}>;

/** The caller must supply an independently finalized ledger view, not an unconfirmed transaction result. */
export type FinalizedProposalLedgerReader = () => Promise<Ledger>;

export type CompactProposalEvidenceSnapshot = GovernedProposalObservation & {
  role: ProposalRole;
  authorizationId: string;
  verifierAuthorizationId: string;
  verifierDidCommitment: string;
  verifierKeyIdCommitment: string;
  verifierSuite: string;
  policyCommitment: string;
  policyVersion: string;
  verifierPublicKey: { x: string; y: string };
  verifierSignature: { announcement: { x: string; y: string }; response: string };
  subjectDidCommitment: string;
  grantPolicyIdCommitment: string;
  proposedAtSequence: string;
  boundActionPayloadHash: string;
  signatureVerified: true;
};

const hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new Error("Malformed Compact proposal evidence record");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export async function resolveCompactProposalObservation(
  readFinalizedLedger: FinalizedProposalLedgerReader,
  expectedRegistryId: string,
  role: ProposalRole,
  authorizationId: string,
): Promise<GovernedProposalObservation | null> {
  if (expectedRegistryId.length === 0 || expectedRegistryId.length > 256
    || authorizationId.length === 0 || authorizationId.length > 256) {
    throw new RangeError("Invalid proposal authorization ID");
  }
  if (!["issuer", "verifier", "auditor", "maintainer", "recognition"].includes(role)) {
    throw new RangeError("Invalid proposal role");
  }
  const key = Buffer.from(sha256Hex(authorizationId).slice(2), "hex");
  const ledger = await readFinalizedLedger();
  if (hex(ledger.registryId) !== sha256Hex(expectedRegistryId)) {
    throw new Error("Finalized ledger belongs to a different trust registry");
  }
  const records = ledger[proposalRecordKeys[role]];
  if (!records.member(key)) return null;
  const record = records.lookup(key);
  return GovernedProposalObservationSchema.parse({
    eventHash: hex(record.proposalGovernanceEventHash),
    evidenceCommitment: hex(record.evidenceCommitment),
  });
}

/** A finalized-ledger projection, not a standalone finality or inclusion proof. */
export async function resolveCompactProposalEvidenceSnapshot(
  readFinalizedLedger: FinalizedProposalLedgerReader,
  expectedRegistryId: string,
  role: ProposalRole,
  authorizationId: string,
  expectedContractAddress: Uint8Array,
): Promise<CompactProposalEvidenceSnapshot | null> {
  if (expectedRegistryId.length === 0 || expectedRegistryId.length > 256
    || authorizationId.length === 0 || authorizationId.length > 256) {
    throw new RangeError("Invalid proposal authorization ID");
  }
  if (!["issuer", "verifier", "auditor", "maintainer", "recognition"].includes(role)) {
    throw new RangeError("Invalid proposal role");
  }
  if (expectedContractAddress.length !== 32 || expectedContractAddress.every((byte) => byte === 0)) {
    throw new RangeError("Expected contract address must be a nonzero 32-byte value");
  }
  const ledger = await readFinalizedLedger();
  if (hex(ledger.registryId) !== sha256Hex(expectedRegistryId)) {
    throw new Error("Finalized ledger belongs to a different trust registry");
  }
  const id = Buffer.from(sha256Hex(authorizationId).slice(2), "hex");
  const records = ledger[proposalRecordKeys[role]];
  if (!records.member(id)) return null;
  const proposal = records.lookup(id);
  const authorizationRecords = ledger[authorizationRecordKeys[role]];
  if (!authorizationRecords.member(id)) {
    throw new Error("Proposal authorization is absent from the finalized ledger");
  }
  const authorization = authorizationRecords.lookup(id);
  const recordedId = "maintainerId" in authorization ? authorization.maintainerId
    : "recognitionId" in authorization ? authorization.recognitionId : authorization.authorizationId;
  const subjectDidCommitment = "maintainerDidCommitment" in authorization
    ? authorization.maintainerDidCommitment
    : "recognizedAuthorityDidCommitment" in authorization
      ? authorization.recognizedAuthorityDidCommitment : authorization.subjectDidCommitment;
  if (hex(recordedId) !== hex(id)) {
    throw new Error("Proposal evidence does not match its authorization record");
  }
  if (!ledger.evidenceVerifierKeyAuthorizationIds.member(proposal.evidenceVerifierAuthorizationId)) {
    throw new Error("Proposal evidence verifier key is absent from the finalized ledger");
  }
  const key = ledger.evidenceVerifierKeyRecords.lookup(proposal.evidenceVerifierAuthorizationId);
  if (hex(key.authorizationId) !== hex(proposal.evidenceVerifierAuthorizationId)
    || hex(key.verifierDidCommitment) !== hex(proposal.evidenceVerifierDidCommitment)
    || hex(key.keyIdCommitment) !== hex(proposal.evidenceVerifierKeyIdCommitment)
    || hex(key.suite) !== hex(proposal.evidenceVerifierSuite)
    || hex(key.policyCommitment) !== hex(proposal.activePolicyCommitment)
    || key.policyVersion !== proposal.activePolicyVersion) {
    throw new Error("Proposal evidence verifier key does not match its ledger snapshot");
  }
  let basePayloadHash: Uint8Array;
  if (role === "issuer") {
    const record = ledger.issuerAuthorizationRecords.lookup(id);
    basePayloadHash = computeCreateIssuerAuthorizationPayloadHash(record.authorizationId, record.subjectDidCommitment,
      record.resourceType, record.resourceId, record.policyId, record.statusPolicyBindingCommitment,
      record.trustLevel, proposal.evidenceCommitment);
  } else if (role === "verifier") {
    const record = ledger.verifierAuthorizationRecords.lookup(id);
    basePayloadHash = computeCreateVerifierAuthorizationPayloadHash(record.authorizationId, record.subjectDidCommitment,
      record.requestResourceId, record.allowedAttributeSetCommitment, record.allowedPredicateSetCommitment,
      record.disclosureLevelCommitment, record.policyId, record.trustLevel, proposal.evidenceCommitment);
  } else if (role === "auditor") {
    const record = ledger.auditorAuthorizationRecords.lookup(id);
    basePayloadHash = computeCreateAuditorAuthorizationPayloadHash(record.authorizationId, record.subjectDidCommitment,
      record.requestResourceId, record.allowedAttributeSetCommitment, record.allowedPredicateSetCommitment,
      record.disclosureLevelCommitment, record.policyId, record.trustLevel, proposal.evidenceCommitment);
  } else if (role === "maintainer") {
    const record = ledger.maintainerMembershipRecords.lookup(id);
    basePayloadHash = computeCreateMaintainerMembershipPayloadHash(record.maintainerId, record.maintainerDidCommitment,
      record.keyId, record.publicKey, record.policyId, record.trustLevel, proposal.evidenceCommitment);
  } else {
    const record = ledger.recognitionRecords.lookup(id);
    basePayloadHash = computeCreateRecognitionPayloadHash(record.recognitionId, record.recognizedAuthorityDidCommitment,
      record.recognizedRegistryId, record.scopeResourceType, record.scopeResourceId, record.policyId,
      record.trustLevel, proposal.evidenceCommitment);
  }
  const { bind, verify } = proposalEvidenceOperations[role];
  const boundActionPayloadHash = bind(basePayloadHash, proposal.evidenceVerifierAuthorizationId,
    proposal.evidenceVerifierKeyIdCommitment, proposal.activePolicyCommitment, proposal.activePolicyVersion);
  if (!verify(key.publicKey, ledger.registryId, ledger.deploymentNetworkIdCommitment,
    expectedContractAddress, proposal.evidenceVerifierKeyIdCommitment,
    boundActionPayloadHash, {
      announcement: proposal.verifierSignatureAnnouncement,
      response: proposal.verifierSignatureResponse,
    })) {
    throw new Error("Proposal evidence verifier signature is invalid");
  }
  return {
    role,
    authorizationId,
    eventHash: hex(proposal.proposalGovernanceEventHash),
    evidenceCommitment: hex(proposal.evidenceCommitment),
    verifierAuthorizationId: hex(proposal.evidenceVerifierAuthorizationId),
    verifierDidCommitment: hex(proposal.evidenceVerifierDidCommitment),
    verifierKeyIdCommitment: hex(proposal.evidenceVerifierKeyIdCommitment),
    verifierSuite: hex(proposal.evidenceVerifierSuite),
    policyCommitment: hex(proposal.activePolicyCommitment),
    policyVersion: proposal.activePolicyVersion.toString(),
    verifierPublicKey: { x: key.publicKey.x.toString(), y: key.publicKey.y.toString() },
    verifierSignature: {
      announcement: {
        x: proposal.verifierSignatureAnnouncement.x.toString(),
        y: proposal.verifierSignatureAnnouncement.y.toString(),
      },
      response: proposal.verifierSignatureResponse.toString(),
    },
    subjectDidCommitment: hex(subjectDidCommitment),
    grantPolicyIdCommitment: hex(authorization.policyId),
    proposedAtSequence: authorization.proposedAtSequence.toString(),
    boundActionPayloadHash: hex(boundActionPayloadHash),
    signatureVerified: true,
  };
}
