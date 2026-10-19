import { MidnightNetwork } from "@midnight-ntwrk/midnight-did";
import { deriveJubjubPublicKeyFromSeed } from "@midnight-ntwrk/trust-registry-contract";
import { EvidenceVerifierKeyStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import { describe, expect, it } from "vitest";

import { createMidnightDid, bytes32Commitment } from "../fixtures.js";
import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";
import {
  EvidenceVerifierDidKeyBindingError,
  EvidenceVerifierDidResolutionUnavailableError,
  verifyEvidenceVerifierDidKeyBinding,
} from "../evidence-verifier-did-key.js";

const did = createMidnightDid("evidence-key-binding");
const methodId = `${did}#assertion-1`;
const publicKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(41));
const rotatedKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(42));
const registered = {
  status: EvidenceVerifierKeyStatus.active,
  verifierDidCommitment: bytes32Commitment(did),
  keyIdCommitment: bytes32Commitment(methodId),
  publicKey,
};
const resolverWith = (key = publicKey, version = 1n) => createMidnightDidResolver([
  createMidnightDidLedgerFixture(did, {
    schnorrJubjubAssertionMethods: [{ id: "assertion-1", publicKey: key }],
    version,
  }),
]);
const verify = (overrides: Partial<Parameters<typeof verifyEvidenceVerifierDidKeyBinding>[0]> = {}) =>
  verifyEvidenceVerifierDidKeyBinding({
    resolver: resolverWith(), expectedNetwork: MidnightNetwork.Undeployed,
    did, verificationMethodId: methodId, registered, ...overrides,
  });

describe("governed evidence verifier DID-key binding", () => {
  it("matches an assertion method, registered commitments, point, and finalized version", async () => {
    let reads = 0;
    const resolver = resolverWith();
    const checked = await verify({
      resolver: { resolveResult: async (subject) => { reads += 1; return resolver.resolveResult(subject); } },
      minimumDidStateVersion: 1n,
    });
    expect(checked.didStateVersion).toBe(1n);
    expect(reads).toBe(1);
  });

  it("rejects wrong network, DID commitment, key commitment, and method subject", async () => {
    await expect(verify({ expectedNetwork: MidnightNetwork.Testnet }))
      .rejects.toBeInstanceOf(EvidenceVerifierDidKeyBindingError);
    await expect(verify({ registered: { ...registered, verifierDidCommitment: bytes32Commitment("wrong") } }))
      .rejects.toThrow(/commitment mismatch/u);
    await expect(verify({ registered: { ...registered, keyIdCommitment: bytes32Commitment("wrong") } }))
      .rejects.toThrow(/commitment mismatch/u);
    await expect(verify({ verificationMethodId: `${createMidnightDid("other")}#assertion-1` }))
      .rejects.toThrow(/commitment mismatch/u);
  });

  it("rejects absent, non-assertion, rotated, low-order, and stale keys", async () => {
    await expect(verify({ resolver: createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, {
        schnorrJubjubAuthenticationMethods: [{ id: "assertion-1", publicKey }],
      }),
    ]) })).rejects.toThrow(/not a current DID assertion key/u);
    await expect(verify({ resolver: createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, {
        schnorrJubjubAssertionMethods: [{ id: "assertion-2", publicKey }],
      }),
    ]) })).rejects.toThrow(/not a current DID assertion key/u);
    await expect(verify({ resolver: resolverWith(rotatedKey, 2n) }))
      .rejects.toThrow(/resolved key or DID version mismatch/u);
    await expect(verify({ registered: { ...registered, publicKey: { x: 0n, y: 1n } } }))
      .rejects.toThrow(/commitment mismatch/u);
    await expect(verify({ registered: { ...registered, status: EvidenceVerifierKeyStatus.suspended } }))
      .rejects.toThrow(/not active/u);
    await expect(verify({ minimumDidStateVersion: 2n }))
      .rejects.toThrow(/resolved key or DID version mismatch/u);
    await expect(verify({ minimumDidStateVersion: 0n }))
      .rejects.toThrow(/invalid minimum DID version/u);
  });

  it("distinguishes an unavailable resolver from an unauthorized method", async () => {
    const unavailable = new Error("upstream unavailable");
    await expect(verify({ resolver: { resolveResult: async () => { throw unavailable; } } }))
      .rejects.toMatchObject({ name: EvidenceVerifierDidResolutionUnavailableError.name, cause: unavailable });
  });

  it("checks the actual Compact key record before and after governed rotation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("did-bound-key-lifecycle");
    const verifierDid = harness.evidenceVerifier.did;
    const firstResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(verifierDid, {
        schnorrJubjubAssertionMethods: [{ id: "assertion-1", publicKey }],
      }),
    ]);
    await expect(harness.verifyCurrentEvidenceVerifierDidKey(firstResolver, MidnightNetwork.Undeployed))
      .resolves.toEqual({ didStateVersion: 1n });

    harness.rotateEvidenceVerifierKey("did-method-rotation");
    await expect(harness.verifyCurrentEvidenceVerifierDidKey(firstResolver, MidnightNetwork.Undeployed))
      .rejects.toThrow(/not a current DID assertion key/u);
    const rotatedResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(verifierDid, {
        schnorrJubjubAssertionMethods: [{ id: "assertion-rotation-1", publicKey: rotatedKey }],
        version: 2n,
      }),
    ]);
    await expect(harness.verifyCurrentEvidenceVerifierDidKey(rotatedResolver, MidnightNetwork.Undeployed))
      .resolves.toEqual({ didStateVersion: 2n });
    harness.suspendEvidenceVerifierKey("did-bound-suspension");
    await expect(harness.verifyCurrentEvidenceVerifierDidKey(rotatedResolver, MidnightNetwork.Undeployed))
      .rejects.toThrow(/not active/u);
  });
});
