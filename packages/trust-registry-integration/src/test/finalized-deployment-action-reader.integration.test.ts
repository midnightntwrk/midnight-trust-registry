import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";
import {
  ContractMaintenanceAuthority,
  ContractOperation,
  ContractState,
  sampleSigningKey,
  signatureVerifyingKey,
} from "@midnight-ntwrk/compact-runtime";
import type { PublicDataProvider } from "@midnight-ntwrk/midnight-js-types";
import {
  bytes32Hex,
  prepareFinalizedDeploymentActionDigest,
} from "@midnight-ntwrk/trust-registry-client";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  TrustRegistrySimulator,
} from "@midnight-ntwrk/trust-registry-contract/testing";

import { bytes32Commitment } from "../fixtures.js";
import {
  createCheckpointedDeploymentActionReader,
  createLocalCheckpointedDeploymentActionReader,
} from "../finalized-deployment-action-reader.js";

const blockHash = "d".repeat(64);
const address = "a".repeat(64);
const registryId = "registry:midnight:qualification";
const policy = bytes32Commitment("policy:qualification");
const bootstrapMaintainerKeyId = bytes32Commitment("maintainer:qualification#key-1");
const verifierCircuit = "authorizeMaintainerAuditEvent";
const verifierKeyPath = process.env.TR_TEST_VERIFIER_KEY_FILE ?? resolve(
  dirname(fileURLToPath(import.meta.url)),
  `../../../../contracts/trust-registry/dist/managed/trust-registry/keys/${verifierCircuit}.verifier`,
);
const realVerifierKeyIt = process.env.TR_TEST_VERIFIER_KEY_FILE || existsSync(verifierKeyPath)
  ? it : it.skip;

function fixture(local = false) {
  const networkId = local ? "undeployed" : "preprod";
  const seed = new Uint8Array(32).fill(13);
  const simulator = new TrustRegistrySimulator({
    registryId: bytes32Commitment(registryId),
    networkIdCommitment: bytes32Commitment(networkId),
    contractAddress: address,
    registryDidCommitment: bytes32Commitment(`did:midnight:${networkId}:qualification`),
    governancePolicyCommitment: policy,
    maintainerId: bytes32Commitment("maintainer:qualification"),
    maintainerDidCommitment: bytes32Commitment(`did:midnight:${networkId}:maintainer`),
    maintainerKeyId: bootstrapMaintainerKeyId,
    maintainerPublicKey: deriveJubjubPublicKeyFromSeed(seed),
    maintainerThreshold: 1n,
  });
  const queryContractState = vi.fn(async () => ({ data: simulator.circuitContext.currentQueryContext.state }));
  const readCurrentFinalizedCheckpoint = vi.fn(async () => ({ networkId, blockHash }));
  const makeReader = local ? createLocalCheckpointedDeploymentActionReader : createCheckpointedDeploymentActionReader;
  const reader = makeReader({
    publicDataProvider: { queryContractState } as unknown as Pick<PublicDataProvider, "queryContractState">,
    checkpointSource: { readCurrentFinalizedCheckpoint },
  });
  return { simulator, reader, queryContractState, readCurrentFinalizedCheckpoint };
}

describe("checkpointed deployment action reader", () => {
  it("decodes real Compact ledger state at the selected finalized block", async () => {
    const { simulator, reader, queryContractState } = fixture();
    const actionState = await reader.readCurrentFinalizedActionState(`0x${address}`);
    expect(queryContractState).toHaveBeenCalledWith(address, { type: "blockHash", blockHash });
    expect(actionState).toEqual({
      networkId: "preprod",
      finalizedBlockHash: `0x${blockHash}`,
      contractAddress: `0x${address}`,
      registryIdCommitment: bytes32Hex(simulator.getLedger().registryId),
      deploymentNetworkIdCommitment: bytes32Hex(simulator.getLedger().deploymentNetworkIdCommitment),
      governancePolicyCommitment: bytes32Hex(simulator.getLedger().governancePolicyCommitment),
      governanceActionSequence: simulator.getLedger().governanceActionCount,
    });
    const finalizedLedger = await reader.readCurrentFinalizedLedger(`0x${address}`);
    expect(finalizedLedger).toMatchObject({
      networkId: "preprod",
      finalizedBlockHash: `0x${blockHash}`,
      contractAddress: `0x${address}`,
    });
    if (finalizedLedger === null) throw new Error("Expected a finalized ledger");
    expect(finalizedLedger.ledger.governanceActionCount).toBe(simulator.getLedger().governanceActionCount);
    expect(bytes32Hex(finalizedLedger.ledger.registryId)).toBe(bytes32Hex(simulator.getLedger().registryId));
    await expect(prepareFinalizedDeploymentActionDigest({
      networkId: "preprod",
      contractAddress: `0x${address}`,
      registryId,
      expectedPolicyCommitment: bytes32Hex(policy),
      expectedActionSequence: simulator.getLedger().governanceActionCount,
      actionKind: encodeCompactActionKind("tr:epoch:publish"),
      actionPayloadHash: bytes32Commitment("epoch:qualification"),
    }, reader)).resolves.toBeDefined();
  });

  it("reads the complete constructor bootstrap at one finalized block", async () => {
    const { simulator, reader, queryContractState } = fixture();
    const observed = await reader.readCurrentFinalizedBootstrapState(`0x${address}`, bootstrapMaintainerKeyId);
    expect(queryContractState).toHaveBeenCalledTimes(1);
    expect(observed).toMatchObject({
      contractVersion: 1n,
      registryDidCommitment: bytes32Hex(simulator.getLedger().registryDidCommitment),
      governancePolicyVersion: 1n,
      governanceActionSequence: 1n,
      maintainerThreshold: 1n,
      emergencyMaintainerThreshold: 1n,
      archivalMaintainerThreshold: 1n,
      activeMaintainerCount: 1n,
      bootstrapMaintainer: {
        maintainerId: bytes32Hex(bytes32Commitment("maintainer:qualification")),
        didCommitment: bytes32Hex(bytes32Commitment("did:midnight:preprod:maintainer")),
        keyId: bytes32Hex(bootstrapMaintainerKeyId),
        status: 0,
        joinedAtSequence: 0n,
      },
    });
    expect((await reader.readCurrentFinalizedBootstrapState(`0x${address}`, bytes32Commitment("other-key")))
      ?.bootstrapMaintainer).toBeNull();
  });

  realVerifierKeyIt("hashes real verifier-key bytes after ContractState serialization at one checkpoint", async () => {
    const { simulator, reader, queryContractState } = fixture();
    const verifierKey = readFileSync(verifierKeyPath);
    const operation = new ContractOperation();
    operation.verifierKey = verifierKey;
    const contractState = new ContractState();
    contractState.data = simulator.circuitContext.currentQueryContext.state;
    contractState.setOperation(verifierCircuit, operation);
    const maintenanceKey = signatureVerifyingKey(sampleSigningKey());
    contractState.maintenanceAuthority = new ContractMaintenanceAuthority([maintenanceKey], 1, 0n);
    queryContractState.mockResolvedValueOnce(ContractState.deserialize(contractState.serialize()) as never);

    const observed = await reader.readCurrentFinalizedDeploymentImage(`0x${address}`, bootstrapMaintainerKeyId);
    expect(queryContractState).toHaveBeenCalledTimes(1);
    expect(observed?.finalizedBlockHash).toBe(`0x${blockHash}`);
    expect(observed?.verifierKeySha256).toEqual({
      [verifierCircuit]: createHash("sha256").update(verifierKey).digest("hex"),
    });
    expect(observed?.maintenanceAuthority).toEqual({
      committee: [`0x${maintenanceKey}`], threshold: 1, counter: 0n,
    });
  });

  it("fails closed when the checkpoint is absent or malformed", async () => {
    const { reader, readCurrentFinalizedCheckpoint, queryContractState } = fixture();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toBeNull();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedLedger(`0x${address}`)).resolves.toBeNull();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce({ networkId: "undeployed", blockHash });
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).rejects.toThrow(/malformed/u);
    expect(queryContractState).not.toHaveBeenCalled();
  });

  it("returns no action context when no state exists at the finalized checkpoint", async () => {
    const { reader, queryContractState } = fixture();
    queryContractState.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toBeNull();
  });

  it("decodes a genesis-pinned local ledger without accepting a public checkpoint", async () => {
    const { reader, simulator, readCurrentFinalizedCheckpoint, queryContractState } = fixture(true);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toMatchObject({
      networkId: "undeployed",
      deploymentNetworkIdCommitment: bytes32Hex(bytes32Commitment("undeployed")),
    });
    expect(queryContractState).toHaveBeenCalledWith(address, { type: "blockHash", blockHash });
    expect(simulator.getLedger().initialized).toBe(true);
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce({ networkId: "preprod", blockHash });
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).rejects.toThrow(/malformed/u);
  });
});
