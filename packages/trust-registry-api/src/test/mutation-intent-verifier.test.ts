import { Buffer } from "node:buffer";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { mutationIntentDigestBytes, type MutationIntent } from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import { verifyMutationIntentDidSignature } from "../mutation-intent-verifier.js";

const seed = new Uint8Array(32).fill(73);
const did = createMidnightDid("mutation-intent-verifier");
const keyId = `${did}#assertion-1`;
const intent: MutationIntent = {
  version: "tr-mutation-intent-v1",
  registryId: "tr:registry:demo",
  actorDid: did,
  actorKeyId: keyId,
  actorRole: "applicant",
  action: "submit",
  target: "auditor",
  targetId: "auth:auditor:alice:v1",
  scopeCommitment: `0x${"11".repeat(32)}`,
  payloadCommitment: `0x${"22".repeat(32)}`,
  nonce: `0x${"33".repeat(32)}`,
  expectedWorkspaceCommitment: `0x${"44".repeat(32)}`,
  expectedEpochId: "epoch:1",
  issuedAt: "2026-10-10T00:00:00.000Z",
  expiresAt: "2026-10-10T00:05:00.000Z",
};

const signatureFor = (value: MutationIntent, signingSeed = seed) => ({
  keyId: value.actorKeyId,
  algorithm: "jubjub-schnorr" as const,
  value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
    signingSeed,
    mutationIntentDigestBytes(value),
  ))).toString("hex")}`,
});

const resolverWithKey = (capabilityInvocation = false) => createMidnightDidResolver([
  createMidnightDidLedgerFixture(did, {
    verificationMethodId: "assertion-1",
    schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
    capabilityInvocation,
  }),
]);

describe("Midnight DID mutation-intent signatures", () => {
  it("verifies applicant authentication and maintainer capability invocation", async () => {
    const resolver = resolverWithKey(true);
    expect(await verifyMutationIntentDidSignature(intent, signatureFor(intent), resolver)).toBe(true);
    const maintainer: MutationIntent = { ...intent, actorRole: "maintainer", action: "approve" };
    expect(await verifyMutationIntentDidSignature(maintainer, signatureFor(maintainer), resolver)).toBe(true);
    expect(await verifyMutationIntentDidSignature(maintainer, signatureFor(maintainer), resolverWithKey())).toBe(false);
  });

  it("rejects wrong key, changed payload, malformed signature, and invalid intent without trapping", async () => {
    const resolver = resolverWithKey();
    const signature = signatureFor(intent);
    expect(await verifyMutationIntentDidSignature({ ...intent, payloadCommitment: `0x${"55".repeat(32)}` }, signature, resolver)).toBe(false);
    expect(await verifyMutationIntentDidSignature(intent, { ...signature, keyId: `${did}#other` }, resolver)).toBe(false);
    expect(await verifyMutationIntentDidSignature(intent, signatureFor(intent, new Uint8Array(32).fill(74)), resolver)).toBe(false);
    expect(await verifyMutationIntentDidSignature(intent, { ...signature, value: `0x${"ff".repeat(96)}` }, resolver)).toBe(false);
    expect(await verifyMutationIntentDidSignature({ ...intent, issuedAt: "not-a-time" }, signature, resolver)).toBe(false);
  });
});
