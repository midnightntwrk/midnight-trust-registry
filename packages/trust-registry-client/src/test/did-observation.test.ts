import { describe, expect, it } from "vitest";
import type { DecisionEvidence } from "@midnight-ntwrk/trust-registry-domain";

import { assertDecisionEvidenceDidMethodMatchesObservation } from "../did-observation.js";

const DID = `did:midnight:devnet:${"1".repeat(64)}`;
const METHOD = `${DID}#key-1`;
const BLOCK = `0x${"a".repeat(64)}`;
const KEY = {
  kty: "EC" as const,
  crv: "Jubjub" as const,
  x: `${"A".repeat(42)}Q`,
  y: `${"B".repeat(42)}g`,
};

const issuerClaim: DecisionEvidence["didMethod"] = {
  did: DID,
  methodId: METHOD,
  methodType: "JsonWebKey",
  controller: DID,
  publicKeyJwk: KEY,
  relationship: "assertionMethod",
  stateVersion: "3",
  stateEvidence: { evidenceType: "ledger-observation", blockHash: BLOCK, transactionHash: BLOCK },
};

const document = () => ({
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
  id: DID,
  verificationMethod: [{ id: METHOD, type: "JsonWebKey", controller: DID, publicKeyJwk: KEY }],
  assertionMethod: [METHOD],
  authentication: [METHOD],
});

const observation = () => ({
  networkId: "devnet",
  blockHash: BLOCK,
  transactionHash: BLOCK,
  stateVersion: "3",
  deactivated: false,
  didDocument: document(),
});

describe("decision evidence DID observation", () => {
  it("rejects a state-proof claim until its DID-ledger proof can be verified", () => {
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation({
      ...issuerClaim,
      stateEvidence: {
        evidenceType: "state-proof",
        stateRoot: BLOCK,
        leafHash: BLOCK,
        path: [BLOCK],
        leafIndex: "0",
        blockHash: BLOCK,
      },
    }, observation(), "devnet")).toThrow(/requires a DID-ledger proof verifier/u);
  });

  it("matches the published Midnight DID document method and role relationship", () => {
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      issuerClaim, observation(), "devnet",
    )).not.toThrow();
    const verifierClaim: DecisionEvidence["didMethod"] = {
      ...issuerClaim,
      relationship: "authentication",
    };
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      verifierClaim, observation(), "devnet",
    )).not.toThrow();
  });

  it("rejects wrong network, block, version, removed method, and substituted key", () => {
    for (const change of [
      { networkId: "mainnet" },
      { blockHash: `0x${"b".repeat(64)}` },
      { transactionHash: `0x${"b".repeat(64)}` },
      { stateVersion: "4" },
      { deactivated: true },
    ]) {
      expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
        issuerClaim, { ...observation(), ...change }, "devnet",
      )).toThrow(/state anchor mismatch/u);
    }
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      issuerClaim,
      { networkId: "devnet", blockHash: BLOCK, stateVersion: "3", deactivated: false, didDocument: document() },
      "devnet",
    )).toThrow(/state anchor mismatch/u);
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      issuerClaim,
      {
        ...observation(),
        didDocument: {
          ...document(),
          verificationMethod: [{ ...document().verificationMethod[0], id: `${DID}#key-2` }],
          assertionMethod: [`${DID}#key-2`],
          authentication: [`${DID}#key-2`],
        },
      },
      "devnet",
    )).toThrow(/absent or ambiguous/u);
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      issuerClaim,
      {
        ...observation(),
        didDocument: {
          ...document(),
          verificationMethod: [{ ...document().verificationMethod[0], publicKeyJwk: { ...KEY, x: `${"C".repeat(42)}Q` } }],
        },
      },
      "devnet",
    )).toThrow(/key mismatch/u);
  });

  it("rejects wrong relationship, controller, and DID subject", () => {
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      issuerClaim,
      { ...observation(), didDocument: { ...document(), assertionMethod: undefined } },
      "devnet",
    )).toThrow(/relationship is absent/u);
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      { ...issuerClaim, controller: `did:midnight:devnet:${"2".repeat(64)}` },
      observation(),
      "devnet",
    )).toThrow(/subject or controller mismatch/u);
    expect(() => assertDecisionEvidenceDidMethodMatchesObservation(
      { ...issuerClaim, did: `did:midnight:devnet:${"2".repeat(64)}` },
      observation(),
      "devnet",
    )).toThrow(/subject or controller mismatch/u);
  });
});
