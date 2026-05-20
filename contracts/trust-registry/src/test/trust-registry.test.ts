import { Buffer } from "node:buffer";

import {
  deriveJubjubPublicKeyFromSeed,
  signMaintainerActionFromSeed,
  verifyMaintainerAction,
} from "../signing.js";
import {
  createMaintainerFixture,
  labelToBytes32,
  TrustRegistrySimulator,
} from "../testing.js";
import {
  MaintainerStatus,
  pureCircuits,
} from "../managed/trust-registry/contract/index.js";

import { describe, expect, it } from "vitest";

describe("trust registry contract", () => {
  it("accepts valid threshold rules and rejects invalid ones", () => {
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 2n)).not.toThrow();
    expect(() => pureCircuits.assertValidMaintainerThreshold(0n, 1n)).toThrow(
      /at least 1/i,
    );
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 4n)).toThrow(
      /may not exceed/i,
    );
    expect(() =>
      pureCircuits.assertSingleSignatureMaintainerThreshold(3n, 2n),
    ).toThrow(/requires threshold 1/i);
  });

  it("initializes the registry with a bootstrap maintainer and records the initial governance event", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 7);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    simulator.initializeRegistry(
      registryId,
      registryDidCommitment,
      governancePolicyCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const state = simulator.getLedger();
    const maintainer = state.maintainerRecords.lookup(bootstrapMaintainer.keyId);

    expect(state.initialized).toBe(true);
    expect(Buffer.from(state.registryId)).toEqual(Buffer.from(registryId));
    expect(Buffer.from(state.registryDidCommitment)).toEqual(
      Buffer.from(registryDidCommitment),
    );
    expect(Buffer.from(state.governancePolicyCommitment)).toEqual(
      Buffer.from(governancePolicyCommitment),
    );
    expect(state.maintainerThreshold).toEqual(1n);
    expect(state.activeMaintainerCount).toEqual(1n);
    expect(state.governanceActionCount).toEqual(1n);
    expect(state.governanceEventHashes.member(state.lastGovernanceEventHash)).toBe(
      true,
    );
    expect(maintainer.status).toEqual(MaintainerStatus.active);
    expect(Buffer.from(maintainer.keyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("rejects invalid initialization payloads and repeated initialization", () => {
    const simulator = new TrustRegistrySimulator();
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 9);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    expect(() =>
      simulator.initializeRegistry(
        new Uint8Array(32),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/Registry id must be set/);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        0n,
      ),
    ).toThrow(/threshold must be at least 1/i);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        2n,
      ),
    ).toThrow(/may not exceed active maintainer count/i);

    simulator.initializeRegistry(
      labelToBytes32("registry:kanon"),
      labelToBytes32("did:midnight:registry"),
      labelToBytes32("policy:kanon:v1"),
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon:second"),
        labelToBytes32("did:midnight:registry:second"),
        labelToBytes32("policy:kanon:v2"),
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/already been initialized/i);
  });

  it("authorizes a signed maintainer action for the bootstrap maintainer", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 3);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    simulator.initializeRegistry(
      registryId,
      registryDidCommitment,
      governancePolicyCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionKind = labelToBytes32("tr:authorize:issuer");
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );

    expect(
      verifyMaintainerAction(
        bootstrapPublicKey,
        registryId,
        actionKind,
        actionPayloadHash,
        actionSequence,
        signature,
      ),
    ).toBe(true);

    const eventHash = simulator.authorizeMaintainerAction(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      actionKind,
      actionPayloadHash,
    );
    const state = simulator.getLedger();

    expect(Buffer.from(eventHash)).toEqual(Buffer.from(state.lastGovernanceEventHash));
    expect(state.governanceEventHashes.member(state.lastGovernanceEventHash)).toBe(
      true,
    );
    expect(state.governanceActionCount).toEqual(2n);
    expect(Buffer.from(state.lastAuthorizedActionKind)).toEqual(
      Buffer.from(actionKind),
    );
    expect(Buffer.from(state.lastAuthorizedActionPayloadHash)).toEqual(
      Buffer.from(actionPayloadHash),
    );
    expect(Buffer.from(state.lastAuthorizedMaintainerKeyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("rejects maintainer actions before initialization and rejects tampered authorization", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const actionKind = labelToBytes32("tr:authorize:issuer");
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 5);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );
    const signatureBeforeInit = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      actionKind,
      actionPayloadHash,
      0n,
    );

    expect(() =>
      simulator.authorizeMaintainerAction(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signatureBeforeInit,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/not initialized/i);

    simulator.initializeRegistry(
      registryId,
      labelToBytes32("did:midnight:registry"),
      labelToBytes32("policy:kanon:v1"),
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionSequence = simulator.getLedger().governanceActionCount;
    const validSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );
    const tamperedSignature = {
      ...validSignature,
      response: validSignature.response + 1n,
    };

    expect(() =>
      simulator.authorizeMaintainerAction(
        labelToBytes32("maintainer:wrong"),
        bootstrapPublicKey,
        validSignature,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/not registered/i);

    expect(() =>
      simulator.authorizeMaintainerAction(
        bootstrapMaintainer.keyId,
        deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19)),
        validSignature,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/does not match the registered key/i);

    expect(() =>
      simulator.authorizeMaintainerAction(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedSignature,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
  });
});
