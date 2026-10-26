import {
  ApplicationEvidenceSubmissionSchema,
  canonicalizeJson,
  computeIssuerStatusPolicyBindingCommitment,
  IssuerStatusPolicyBindingSchema,
  sha256Hex,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";
import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";
import { z } from "zod";

import type { LocalLedgerRuntimePlan } from "./local-ledger-runtime.js";
import { PendingApplicationRecordSchema, type PendingApplicationRecord } from "./pending-application-registration.js";
import { ApplicationVpReceiptSchema } from "./application-vp-http.js";
import {
  assertProposalAdmissionRecords,
  type AcceptedApplicationEvidence,
} from "./proposal-admission.js";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u)
  .refine((value) => !/^0x0{64}$/u.test(value));
const ExactTrustLevelSchema = z.string().min(1).max(128).refine((value) =>
  value === value.trim() && value === value.normalize("NFC")
  && [...value].every((char) => {
    const point = char.codePointAt(0)!;
    return point > 0x1f && (point < 0x7f || point > 0x9f)
      && (point < 0xd800 || point > 0xdfff);
  })
  && !/\p{Default_Ignorable_Code_Point}/u.test(value));
const AcceptedEvidenceRecordSchema = z.strictObject({
  evidence: ApplicationEvidenceSubmissionSchema,
  receipt: ApplicationVpReceiptSchema,
});

export const LocalIssuerProposalTermsSchema = z.strictObject({
  format: z.literal("tr-local-issuer-proposal-terms-v1"),
  networkId: z.literal(getLocalNetworkProfile().networkId),
  contractAddress: Bytes32Schema,
  expectedGenesisHash: Bytes32Schema,
  applicationId: z.string().min(1).max(256),
  authorizationId: z.string().min(1).max(256),
  evidenceCommitment: Bytes32Schema,
  trustLevel: ExactTrustLevelSchema,
  statusPolicyBinding: IssuerStatusPolicyBindingSchema,
});

export type LocalIssuerProposalTerms = z.infer<typeof LocalIssuerProposalTermsSchema>;

/** Structural binding only: the accepted VP and VC status authority need their own live verification. */
export function bindAcceptedLocalIssuerProposalTerms(input: {
  terms: unknown;
  pending: PendingApplicationRecord | null;
  accepted: AcceptedApplicationEvidence | null;
  submittedEvidence: ApplicationEvidenceSubmission;
  plan: Pick<LocalLedgerRuntimePlan, "networkId" | "contractAddress" | "expectedGenesisHash">;
  /** Must come from the independently authenticated current-ledger selection. */
  currentPolicy: { registryId: string; policyId: string; version: string };
}): {
  terms: LocalIssuerProposalTerms;
  reviewBindingSha256: string;
  statusPolicyBindingCommitment: string;
} {
  const terms = LocalIssuerProposalTermsSchema.parse(input.terms);
  assertProposalAdmissionRecords(input.pending, input.accepted, "issuer",
    terms.authorizationId, input.submittedEvidence);
  const pending = PendingApplicationRecordSchema.parse(input.pending);
  const accepted = AcceptedEvidenceRecordSchema.parse(input.accepted);
  if (input.plan.networkId !== getLocalNetworkProfile().networkId
    || terms.networkId !== input.plan.networkId
    || terms.contractAddress !== input.plan.contractAddress
    || terms.expectedGenesisHash !== input.plan.expectedGenesisHash
    || terms.applicationId !== pending.binding.applicationId
    || terms.evidenceCommitment !== accepted.evidence.commitment
    || input.currentPolicy.registryId !== pending.binding.registryId
    || input.currentPolicy.policyId !== pending.binding.policyId
    || input.currentPolicy.version !== pending.binding.policyVersion
    || terms.statusPolicyBinding.trustRegistryId !== pending.binding.registryId
    || terms.statusPolicyBinding.issuerAuthorizationId !== pending.authorizationId) {
    throw new Error("Issuer proposal terms do not bind the accepted application and approved local deployment");
  }
  return {
    terms,
    reviewBindingSha256: sha256Hex(`tr:local-issuer-review-binding:v1\0${canonicalizeJson({
      terms, currentPolicy: input.currentPolicy, pendingApplication: pending,
      acceptedEvidence: accepted.evidence, acceptedReceipt: accepted.receipt,
    })}`),
    statusPolicyBindingCommitment: computeIssuerStatusPolicyBindingCommitment(terms.statusPolicyBinding),
  };
}
