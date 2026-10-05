import { Buffer } from "node:buffer";

import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import {
  decodeJubjubSignature,
  deriveJubjubPublicKeyFromSeed,
  verifyApplicationEvidenceCommitmentSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { describe, expect, it } from "vitest";

import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import { bytes32Commitment, createIssuerScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("application evidence DID assertion-key fixture", () => {
  it("resolves the verifier's native assertion key and verifies its signed commitment", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("did-attestation");
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scopeCommitment: issuer.resourceIdCommitment,
    });
    const did = parseMidnightDIDString(harness.evidenceVerifier.did);
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(41)),
      }),
    ]);
    const method = await resolveMidnightDIDMethodBinding({
      resolver,
      did,
      verificationMethodId: "#assertion-1",
      relationship: "assertionMethod",
    });

    expect(evidence.signature.keyId).toBe(`${did}#assertion-1`);
    expect(verifyApplicationEvidenceCommitmentSignature(
      method.publicKey,
      Buffer.from(evidence.commitment.slice(2), "hex"),
      bytes32Commitment(evidence.signature.keyId),
      decodeJubjubSignature(Buffer.from(evidence.signature.value.slice(2), "hex")),
    )).toBe(true);
    expect(verifyApplicationEvidenceCommitmentSignature(
      method.publicKey,
      bytes32Commitment("another-application"),
      bytes32Commitment(evidence.signature.keyId),
      decodeJubjubSignature(Buffer.from(evidence.signature.value.slice(2), "hex")),
    )).toBe(false);
    await expect(resolveMidnightDIDMethodBinding({
      resolver,
      did,
      verificationMethodId: "#assertion-1",
      relationship: "capabilityInvocation",
    })).rejects.toThrow(/not authorized/);
  });
});
