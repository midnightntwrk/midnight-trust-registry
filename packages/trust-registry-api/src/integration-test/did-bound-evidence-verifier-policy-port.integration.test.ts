import { Buffer } from "node:buffer";

import { MidnightNetwork } from "@midnight-ntwrk/midnight-did";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { EvidenceVerifierKeyStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  bytes32Commitment,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  LocalTrustRegistryIntegrationHarness,
} from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import {
  createDidBoundEvidenceVerifierPolicyPort,
  type EvidenceVerifierDidAuthoritySource,
} from "../did-bound-evidence-verifier-policy-port.js";
import {
  GovernedPolicyActionRejectedError,
  type PreparedGovernedPolicyAction,
  type GovernedEvidenceVerifierTransitionInput,
  type GovernedPolicyActionPort,
} from "../governed-policy-actions.js";
import { createTrustRegistryApiServer } from "../server.js";

const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

const setup = () => {
  const harness = new LocalTrustRegistryIntegrationHarness("did-guarded-policy");
  const label = "replacement";
  const prepared = harness.prepareEvidenceVerifierRotationAction(label);
  const newAuthorizationId = prepared.newAuthorizationId!;
  const newKeyIdCommitment = prepared.newKeyIdCommitment!;
  const newPublicKey = prepared.newPublicKey!;
  const did = harness.evidenceVerifier.did;
  const methodId = `${did}#assertion-rotation-1`;
  let currentKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(42));
  let resolverUnavailable = false;
  let executions = 0;
  let reads = 0;
  let payloadOverride: Uint8Array | undefined;
  const input: GovernedEvidenceVerifierTransitionInput = {
    action: "rotate",
    authorizationId: hex(prepared.authorizationId),
    reasonHash: hex(prepared.reasonHash),
    newAuthorizationId: hex(newAuthorizationId),
    newKeyIdCommitment: hex(newKeyIdCommitment),
    newPublicKey: {
      x: newPublicKey.x.toString(),
      y: newPublicKey.y.toString(),
    },
  };
  const base: GovernedPolicyActionPort = {
    async prepareThresholds() { throw new GovernedPolicyActionRejectedError(); },
    async executeThresholds() { throw new GovernedPolicyActionRejectedError(); },
    async prepareEvidenceVerifier() { throw new GovernedPolicyActionRejectedError(); },
    async executeEvidenceVerifier() { throw new GovernedPolicyActionRejectedError(); },
    async prepareEvidenceVerifierTransition() {
      const context = harness.prepareEvidenceVerifierRotationAction(label);
      return payloadOverride === undefined ? context : { ...context, actionPayloadHash: payloadOverride };
    },
    async executeEvidenceVerifierTransition(_input, signers) {
      executions += 1;
      return { eventHash: hex(harness.executeEvidenceVerifierRotationWithSignatures(label, signers)) };
    },
  };
  const authority: EvidenceVerifierDidAuthoritySource = {
    expectedNetwork: MidnightNetwork.Undeployed,
    resolver: {
      resolveResult: async (subject) => {
        reads += 1;
        if (resolverUnavailable) throw new Error("DID reader offline");
        return createMidnightDidResolver([
          createMidnightDidLedgerFixture(did, {
            schnorrJubjubAssertionMethods: [{ id: "assertion-rotation-1", publicKey: currentKey }],
            version: 2n,
          }),
        ]).resolveResult(subject);
      },
    },
    async readRegistrationCandidate() { throw new GovernedPolicyActionRejectedError(); },
    async readRotationCandidate() {
      return {
        did, verificationMethodId: methodId,
        minimumDidStateVersion: 2n,
        key: {
          verifierDidCommitment: bytes32Commitment(did),
          keyIdCommitment: bytes32Commitment(methodId),
          publicKey: newPublicKey,
        },
        oldRecord: harness.simulator.getEvidenceVerifierKey(prepared.authorizationId),
      };
    },
  };
  const port = createDidBoundEvidenceVerifierPolicyPort(base, authority);
  const signer = {
    keyId: bytes32Commitment(`${harness.maintainerDid}#key-1`),
    publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(17)),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      new Uint8Array(32).fill(17), prepared.registryId, prepared.networkIdCommitment,
      prepared.contractAddress, prepared.policyCommitment, prepared.actionKind,
      prepared.actionPayloadHash, prepared.actionSequence,
    ),
  };
  return {
    harness, input, port, prepared, signer, newAuthorizationId,
    setCurrentKey: (key: typeof currentKey) => { currentKey = key; },
    setResolverUnavailable: (unavailable: boolean) => { resolverUnavailable = unavailable; },
    setPayloadOverride: (payload: Uint8Array) => { payloadOverride = payload; },
    reads: () => reads,
    executions: () => executions,
  };
};

describe("DID-bound governed evidence-verifier policy port", () => {
  it("resolves the assertion method again before executing a Compact rotation", async () => {
    const state = setup();
    await expect(state.port.prepareEvidenceVerifierTransition!(state.input)).resolves.toBeDefined();
    await expect(state.port.executeEvidenceVerifierTransition!(state.input, [state.signer]))
      .resolves.toHaveProperty("eventHash");
    expect(state.reads()).toBe(2);
    expect(state.executions()).toBe(1);
    expect(state.harness.simulator.getEvidenceVerifierKey(state.newAuthorizationId).status)
      .toBe(EvidenceVerifierKeyStatus.active);
  });

  it("rejects a DID method rotated away after prepare without executing", async () => {
    const state = setup();
    await state.port.prepareEvidenceVerifierTransition!(state.input);
    state.setCurrentKey(deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(43)));
    await expect(state.port.executeEvidenceVerifierTransition!(state.input, [state.signer]))
      .rejects.toBeInstanceOf(GovernedPolicyActionRejectedError);
    expect(state.executions()).toBe(0);
  });

  it("rejects a replacement request that differs from the exact Compact action", async () => {
    const state = setup();
    if (state.input.action !== "rotate") throw new Error("rotation fixture required");
    await expect(state.port.prepareEvidenceVerifierTransition!({
      ...state.input, newKeyIdCommitment: hex(bytes32Commitment("unrelated-key")),
    })).rejects.toBeInstanceOf(GovernedPolicyActionRejectedError);
    expect(state.executions()).toBe(0);
  });

  it("rejects a valid DID key when the prepared Compact payload is substituted", async () => {
    const state = setup();
    state.setPayloadOverride(bytes32Commitment("substituted-rotation-payload"));
    await expect(state.port.prepareEvidenceVerifierTransition!(state.input))
      .rejects.toBeInstanceOf(GovernedPolicyActionRejectedError);
    expect(state.executions()).toBe(0);
  });

  it("binds registration preparation to the candidate assertion method and payload", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("did-guarded-registration");
    const prepared = harness.prepareEvidenceVerifierRegistrationAction();
    const did = harness.evidenceVerifier.did;
    let candidateKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(41));
    const base: GovernedPolicyActionPort = {
      async prepareThresholds() { throw new GovernedPolicyActionRejectedError(); },
      async executeThresholds() { throw new GovernedPolicyActionRejectedError(); },
      async prepareEvidenceVerifier() { return prepared; },
      async executeEvidenceVerifier() { throw new GovernedPolicyActionRejectedError(); },
    };
    const port = createDidBoundEvidenceVerifierPolicyPort(base, {
      expectedNetwork: MidnightNetwork.Undeployed,
      resolver: createMidnightDidResolver([createMidnightDidLedgerFixture(did, {
        schnorrJubjubAssertionMethods: [{ id: "assertion-1", publicKey: candidateKey }],
      })]),
      async readRegistrationCandidate() {
        return {
          did, verificationMethodId: `${did}#assertion-1`,
          key: {
            verifierDidCommitment: bytes32Commitment(did),
            keyIdCommitment: bytes32Commitment(`${did}#assertion-1`),
            publicKey: candidateKey,
          },
        };
      },
      async readRotationCandidate() { throw new GovernedPolicyActionRejectedError(); },
    });
    await expect(port.prepareEvidenceVerifier()).resolves.toBeDefined();
    candidateKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(43));
    await expect(port.prepareEvidenceVerifier()).rejects.toBeInstanceOf(GovernedPolicyActionRejectedError);
  });

  it("maps DID authority failures at the governed HTTP boundary and still executes a valid rotation", async () => {
    const state = setup();
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(state.harness, {
        label: "did-guarded-policy-http",
      }) },
      governedPolicyActions: state.port,
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/policy/evidence-verifier/rotate`;
      if (state.input.action !== "rotate") throw new Error("rotation fixture required");
      const rotation = {
        authorizationId: state.input.authorizationId,
        reasonHash: state.input.reasonHash,
        newAuthorizationId: state.input.newAuthorizationId,
        newKeyIdCommitment: state.input.newKeyIdCommitment,
        newPublicKey: state.input.newPublicKey,
      };
      const post = (path: string, body: unknown) => fetch(`${endpoint}/${path}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      state.setResolverUnavailable(true);
      const unavailable = await post("prepare", rotation);
      expect(unavailable.status).toBe(503);
      expect((await unavailable.json()).type).toMatch(/evidence-verifier-did-unavailable/u);
      expect(state.executions()).toBe(0);
      state.setResolverUnavailable(false);
      state.setCurrentKey(deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(43)));
      const rejected = await post("prepare", rotation);
      expect(rejected.status).toBe(403);
      expect((await rejected.json()).type).toMatch(/governed-policy-rejected/u);
      expect(state.executions()).toBe(0);
      state.setCurrentKey(deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(42)));
      const ready = await post("prepare", rotation);
      expect(ready.status).toBe(200);
      const prepared = await ready.json() as PreparedGovernedPolicyAction;
      const signer = {
        keyId: hex(state.signer.keyId),
        publicKey: {
          x: state.signer.publicKey.x.toString(),
          y: state.signer.publicKey.y.toString(),
        },
        signature: hex(encodeJubjubSignature(state.signer.signature)),
      };
      const rotated = await post("submit", { ...rotation, prepared, signers: [signer] });
      expect(rotated.status).toBe(202);
      expect(state.executions()).toBe(1);
      expect(state.harness.simulator.getEvidenceVerifierKey(state.newAuthorizationId).status)
        .toBe(EvidenceVerifierKeyStatus.active);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => {
        if (error) reject(error);
        else resolve();
      }));
    }
  });
});
