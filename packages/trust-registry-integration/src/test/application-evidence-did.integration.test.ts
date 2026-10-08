import { Buffer } from "node:buffer";

import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import {
  decodeJubjubSignature,
  deriveJubjubPublicKeyFromSeed,
  signApplicationEvidenceCommitmentFromSeed,
  verifyApplicationEvidenceCommitmentSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { describe, expect, it } from "vitest";

import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import { bytes32Commitment, createIssuerAuthorizationScopeFixture, createIssuerScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("application evidence DID assertion-key fixture", () => {
  it("resolves the verifier's native assertion key and verifies its signed commitment", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("did-attestation");
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: "credentialFamily", id: issuer.resourceId },
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
      bytes32Commitment(evidence.signature.keyId),
      Buffer.from(evidence.commitment.slice(2), "hex"),
      decodeJubjubSignature(Buffer.from(evidence.signature.value.slice(2), "hex")),
    )).toBe(true);
    expect(verifyApplicationEvidenceCommitmentSignature(
      method.publicKey,
      bytes32Commitment(evidence.signature.keyId),
      bytes32Commitment("another-application"),
      decodeJubjubSignature(Buffer.from(evidence.signature.value.slice(2), "hex")),
    )).toBe(false);
    await expect(resolveMidnightDIDMethodBinding({
      resolver,
      did,
      verificationMethodId: "#assertion-1",
      relationship: "capabilityInvocation",
    })).rejects.toThrow(/not authorized/);
  });

  it("selects the named assertion key and rejects a retired key after rotation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("did-key-rotation");
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scopeCommitment: issuer.resourceIdCommitment,
    });
    const did = parseMidnightDIDString(harness.evidenceVerifier.did);
    const firstKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(41));
    const secondSeed = new Uint8Array(32).fill(42);
    const secondKey = deriveJubjubPublicKeyFromSeed(secondSeed);
    const methods = [
      { id: "assertion-1", publicKey: firstKey },
      { id: "assertion-2", publicKey: secondKey },
    ];
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, { schnorrJubjubAssertionMethods: methods }),
    ]);
    const first = await resolveMidnightDIDMethodBinding({
      resolver, did, verificationMethodId: "#assertion-1", relationship: "assertionMethod",
    });
    const second = await resolveMidnightDIDMethodBinding({
      resolver, did, verificationMethodId: "#assertion-2", relationship: "assertionMethod",
    });
    const commitment = Buffer.from(evidence.commitment.slice(2), "hex");
    const firstSignature = decodeJubjubSignature(Buffer.from(evidence.signature.value.slice(2), "hex"));
    expect(verifyApplicationEvidenceCommitmentSignature(
      first.publicKey, bytes32Commitment(evidence.signature.keyId), commitment, firstSignature,
    )).toBe(true);
    expect(verifyApplicationEvidenceCommitmentSignature(
      second.publicKey, bytes32Commitment(evidence.signature.keyId), commitment, firstSignature,
    )).toBe(false);

    const rotatedResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, {
        schnorrJubjubAssertionMethods: [methods[1]!], version: 2n, updated: 3n,
      }),
    ]);
    await expect(resolveMidnightDIDMethodBinding({
      resolver: rotatedResolver, did, verificationMethodId: "#assertion-1", relationship: "assertionMethod",
    })).rejects.toThrow();
    const active = await resolveMidnightDIDMethodBinding({
      resolver: rotatedResolver, did, verificationMethodId: "#assertion-2", relationship: "assertionMethod",
    });
    const activeKeyId = `${did}#assertion-2`;
    const activeSignature = signApplicationEvidenceCommitmentFromSeed(
      secondSeed, bytes32Commitment(activeKeyId), commitment,
    );
    expect(verifyApplicationEvidenceCommitmentSignature(
      active.publicKey, bytes32Commitment(activeKeyId), commitment, activeSignature,
    )).toBe(true);
  });
});
