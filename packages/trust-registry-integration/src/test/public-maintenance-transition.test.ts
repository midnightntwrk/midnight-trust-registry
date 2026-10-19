import { createHash } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { MaintenanceUpdate, ReplaceAuthority, signData, verifySignature } from "@midnight-ntwrk/midnight-js-protocol/ledger";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import { deriveJubjubPublicKeyFromSeed, MaintainerStatus, TrustRegistryContract, trustRegistryWitnesses } from "@midnight-ntwrk/trust-registry-contract";

import type { FinalizedRegistryDeploymentImage } from "../finalized-deployment-action-reader.js";
import {
  prepareCommitteeTransitionFromFinalizedImage,
  preparePublicNetworkCommitteeTransition,
  type CommitteeTransitionApproval,
} from "../public-maintenance-transition.js";

const mocks = vi.hoisted(() => ({
  createReader: vi.fn(),
  readImage: vi.fn(),
}));

vi.mock("../public-network-deployment-action-reader.js", () => ({
  createPublicNetworkDeploymentActionReader: mocks.createReader,
}));

const address = `0x${"a".repeat(64)}`;
const finalizedBlockHash = `0x${"b".repeat(64)}`;
const bootstrapKey = sampleSigningKey();
const bootstrapVerifyingKey = `0x${signatureVerifyingKey(bootstrapKey)}`;
const committeeKeys = Array.from({ length: 3 }, () => `0x${signatureVerifyingKey(sampleSigningKey())}`);
const bootstrap = {
  registryId: "registry:committee-transition-test",
  registryDidCommitment: bytes32Commitment("did:midnight:preprod:registry"),
  governancePolicyCommitment: bytes32Commitment("governance:initial"),
  maintainerId: bytes32Commitment("maintainer:bootstrap"),
  maintainerDidCommitment: bytes32Commitment("did:midnight:preprod:bootstrap"),
  maintainerKeyId: bytes32Commitment("maintainer:bootstrap#key-1"),
  maintainerPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(17)),
  maintainerThreshold: 1n,
};
const governance = {
  policyCommitment: bytes32Commitment("governance:three-maintainers"),
  policyVersion: 2n,
  actionSequence: 4n,
  maintainerThreshold: 2n,
  activeMaintainerCount: 3n,
};
const verifierKeySha256 = Object.fromEntries(
  Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits)
    .map((name) => [name, createHash("sha256").update(`vk:${name}`).digest("hex")]),
);
const releaseManifest = {
  format: "tr-release-candidate-manifest-v2" as const,
  verifierKeySha256,
};
const approval = (): CommitteeTransitionApproval => ({
  network: {
    networkId: "preprod",
    rpcUrl: "https://rpc.example.test/",
    indexerHttpUrl: "https://indexer.example.test/graphql",
    indexerWsUrl: "wss://indexer.example.test/graphql/ws",
    expectedGenesisHash: `0x${"c".repeat(64)}`,
  },
  receipt: {
    networkId: "preprod", contractAddress: address,
    txId: "deployment-tx", blockHash: `0x${"d".repeat(64)}`, blockHeight: 10,
  },
  bootstrap,
  releaseManifest,
  governance,
  maintenancePolicy: { mode: "committee", verifyingKeys: committeeKeys, threshold: 2 },
  bootstrapMaintenanceVerifyingKey: bootstrapVerifyingKey,
  expiresAt: new Date(Date.now() + 5 * 60_000),
});
const image = (): FinalizedRegistryDeploymentImage => ({
  networkId: "preprod",
  finalizedBlockHash,
  contractAddress: address,
  registryIdCommitment: bytes32Hex(bytes32Commitment(bootstrap.registryId)),
  deploymentNetworkIdCommitment: bytes32Hex(bytes32Commitment("preprod")),
  governancePolicyCommitment: bytes32Hex(governance.policyCommitment),
  governancePolicyVersion: governance.policyVersion,
  governanceActionSequence: governance.actionSequence,
  contractVersion: 1n,
  registryDidCommitment: bytes32Hex(bootstrap.registryDidCommitment),
  maintainerThreshold: governance.maintainerThreshold,
  emergencyMaintainerThreshold: 1n,
  archivalMaintainerThreshold: 1n,
  activeMaintainerCount: governance.activeMaintainerCount,
  bootstrapMaintainer: {
    maintainerId: bytes32Hex(bootstrap.maintainerId),
    didCommitment: bytes32Hex(bootstrap.maintainerDidCommitment),
    keyId: bytes32Hex(bootstrap.maintainerKeyId),
    publicKey: bootstrap.maintainerPublicKey,
    status: MaintainerStatus.active,
    joinedAtSequence: 0n,
  },
  verifierKeySha256,
  maintenanceAuthority: {
    committee: [bootstrapVerifyingKey], threshold: 1, counter: 0n,
  },
});

beforeEach(() => {
  vi.clearAllMocks();
  setNetworkId("preprod");
  mocks.createReader.mockReturnValue({ readCurrentFinalizedDeploymentImage: mocks.readImage });
  mocks.readImage.mockResolvedValue(image());
});

describe("public maintenance committee transition", () => {
  it("builds a counter-one, two-of-three update and accepts only the bootstrap signature", () => {
    const plan = prepareCommitteeTransitionFromFinalizedImage(approval(), image());
    expect(plan.contractAddress).toBe(address);
    expect(plan.networkId).toBe("preprod");
    expect(plan.finalizedBlockHash).toBe(finalizedBlockHash);
    expect(plan.committeeVerifyingKeys).toEqual(committeeKeys);
    expect(plan.threshold).toBe(2);
    expect(plan.currentAuthorityCounter).toBe(0n);
    expect(plan.nextAuthorityCounter).toBe(1n);
    expect(plan.dataToSign.length).toBeGreaterThan(0);
    const tx = plan.authorize(signData(bootstrapKey, plan.dataToSign));
    expect(tx.serialize().length).toBeGreaterThan(0);
    const actions = [...(tx.intents?.values() ?? [])].flatMap((intent) => intent.actions);
    expect(actions).toHaveLength(1);
    const update = actions[0];
    expect(update).toBeInstanceOf(MaintenanceUpdate);
    const maintenanceUpdate = update as MaintenanceUpdate;
    expect(maintenanceUpdate.address).toBe(address.slice(2));
    expect(maintenanceUpdate.counter).toBe(0n);
    expect(maintenanceUpdate.signatures).toHaveLength(1);
    expect(maintenanceUpdate.signatures[0]?.[0]).toBe(0n);
    expect(verifySignature(bootstrapVerifyingKey.slice(2), maintenanceUpdate.dataToSign,
      maintenanceUpdate.signatures[0]![1])).toBe(true);
    expect(maintenanceUpdate.updates).toHaveLength(1);
    expect(maintenanceUpdate.updates[0]).toBeInstanceOf(ReplaceAuthority);
    const replacement = maintenanceUpdate.updates[0] as ReplaceAuthority;
    expect(replacement.authority.committee).toEqual(committeeKeys.map((key) => key.slice(2)));
    expect(replacement.authority.threshold).toBe(2);
    expect(replacement.authority.counter).toBe(1n);
    expect(() => plan.authorize(signData(sampleSigningKey(), plan.dataToSign)))
      .toThrow(/signature is invalid/u);
  });

  it("does not let callers mutate the returned signing bytes after preparation", () => {
    const plan = prepareCommitteeTransitionFromFinalizedImage(approval(), image());
    plan.dataToSign.fill(0);
    expect(() => plan.authorize(signData(bootstrapKey, plan.dataToSign)))
      .toThrow(/signature is invalid/u);
  });

  it("reads the pinned finalized image before constructing any signable update", async () => {
    const input = approval();
    const plan = await preparePublicNetworkCommitteeTransition(input);
    expect(mocks.createReader).toHaveBeenCalledWith(input.network);
    expect(mocks.readImage).toHaveBeenCalledWith(address, bootstrap.maintainerKeyId);
    expect(plan.nextAuthorityCounter).toBe(1n);
    mocks.readImage.mockResolvedValueOnce(null);
    await expect(preparePublicNetworkCommitteeTransition(input))
      .rejects.toThrow(/image is unavailable/u);
  });

  it.each([
    ["wrong contract address", { contractAddress: `0x${"e".repeat(64)}` }],
    ["wrong network", { networkId: "preview" }],
    ["wrong registry", { registryIdCommitment: `0x${"e".repeat(64)}` }],
    ["wrong governance", { governanceActionSequence: 5n }],
    ["missing verifier key", { verifierKeySha256: {} }],
    ["wrong verifier key", { verifierKeySha256: {
      ...verifierKeySha256, [Object.keys(verifierKeySha256)[0]!]: "e".repeat(64),
    } }],
    ["stale maintenance counter", { maintenanceAuthority: {
      committee: [bootstrapVerifyingKey], threshold: 1, counter: 1n,
    } }],
    ["replaced maintenance key", { maintenanceAuthority: {
      committee: [committeeKeys[0]!], threshold: 1, counter: 0n,
    } }],
    ["malformed finalized block", { finalizedBlockHash: "0x0" }],
  ])("rejects %s", (_label, change) => {
    expect(() => prepareCommitteeTransitionFromFinalizedImage(approval(), { ...image(), ...change }))
      .toThrow();
  });

  it.each([
    { verifyingKeys: committeeKeys, threshold: 1 },
    { verifyingKeys: [committeeKeys[0]!, committeeKeys[0]!, committeeKeys[2]!], threshold: 2 },
    { verifyingKeys: committeeKeys.slice(0, 2), threshold: 2 },
    { verifyingKeys: committeeKeys, threshold: 4 },
  ])("rejects weak or malformed committee policy %#", (policy) => {
    const input = approval();
    input.maintenancePolicy = { mode: "committee", ...policy };
    expect(() => prepareCommitteeTransitionFromFinalizedImage(input, image()))
      .toThrow(/committee policy/u);
  });

  it("rejects a syntactically canonical key that Ledger 8 cannot verify", () => {
    const input = approval();
    input.maintenancePolicy = {
      mode: "committee",
      verifyingKeys: [committeeKeys[0]!, committeeKeys[1]!, `0x${"f".repeat(64)}`],
      threshold: 2,
    };
    expect(() => prepareCommitteeTransitionFromFinalizedImage(input, image()))
      .toThrow(/Malformed Schnorr verifying key/u);
  });

  it("rejects weak governance, expired approvals, and network changes", () => {
    const weak = approval();
    weak.governance = { ...governance, activeMaintainerCount: 2n };
    expect(() => prepareCommitteeTransitionFromFinalizedImage(weak, image()))
      .toThrow(/multi-party governance/u);
    const expired = approval();
    expired.expiresAt = new Date(Date.now() - 1000);
    expect(() => prepareCommitteeTransitionFromFinalizedImage(expired, image()))
      .toThrow(/expiry/u);
    const plan = prepareCommitteeTransitionFromFinalizedImage(approval(), image());
    setNetworkId("preview");
    expect(() => plan.authorize(signData(bootstrapKey, plan.dataToSign)))
      .toThrow(/network changed/u);
  });

  it("refuses a signature after the prepared transaction expires", () => {
    vi.useFakeTimers();
    try {
      const now = new Date("2026-10-19T00:00:00.000Z");
      vi.setSystemTime(now);
      const input = approval();
      input.expiresAt = new Date(now.getTime() + 1000);
      const plan = prepareCommitteeTransitionFromFinalizedImage(input, image());
      const signature = signData(bootstrapKey, plan.dataToSign);
      vi.setSystemTime(input.expiresAt);
      expect(() => plan.authorize(signature)).toThrow(/window expired/u);
    } finally {
      vi.useRealTimers();
    }
  });
});
