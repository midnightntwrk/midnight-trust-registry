import { Buffer } from "node:buffer";

import type { TrustRegistrySimulator } from "@midnight-ntwrk/trust-registry-contract/testing";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

import {
  GovernedProposalObservationSchema,
  type GovernedProposalObservation,
} from "./governed-proposal-observation.js";

type Ledger = ReturnType<TrustRegistrySimulator["getLedger"]>;
export type ProposalRole = "issuer" | "verifier" | "auditor" | "maintainer";

/** The caller must supply an independently finalized ledger view, not an unconfirmed transaction result. */
export type FinalizedProposalLedgerReader = () => Promise<Ledger>;

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
  const key = Buffer.from(sha256Hex(authorizationId).slice(2), "hex");
  const ledger = await readFinalizedLedger();
  if (hex(ledger.registryId) !== sha256Hex(expectedRegistryId)) {
    throw new Error("Finalized ledger belongs to a different trust registry");
  }
  const records = role === "issuer" ? ledger.issuerProposalEvidenceRecords
    : role === "verifier" ? ledger.verifierProposalEvidenceRecords
      : role === "auditor" ? ledger.auditorProposalEvidenceRecords
        : ledger.maintainerProposalEvidenceRecords;
  if (!records.member(key)) return null;
  const record = records.lookup(key);
  return GovernedProposalObservationSchema.parse({
    eventHash: hex(record.proposalGovernanceEventHash),
    evidenceCommitment: hex(record.evidenceCommitment),
  });
}
