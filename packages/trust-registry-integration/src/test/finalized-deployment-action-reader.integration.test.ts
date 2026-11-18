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
import { SerializedContractState, type PublicDataProvider } from "@midnight-ntwrk/midnight-js-types";
import {
  bytes32Hex,
  prepareFinalizedDeploymentActionDigest,
} from "@midnightntwrk/trust-registry-client";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
} from "@midnightntwrk/trust-registry-contract";
import {
  TrustRegistrySimulator,
} from "@midnightntwrk/trust-registry-contract/testing";

import { bytes32Commitment } from "../fixtures.js";
import {
  createCheckpointedDeploymentActionReader,
  createLocalCheckpointedDeploymentActionReader,
} from "../finalized-deployment-action-reader.js";
import { maintenanceVerifyingKeyHex } from "../maintenance-verifying-key.js";

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
const hasRealVerifierKey = Boolean(process.env.TR_TEST_VERIFIER_KEY_FILE) || existsSync(verifierKeyPath);
const realVerifierKeyIt = hasRealVerifierKey ? it : it.skip;

const networkRead = (state: ContractState) => ({
  contractState: SerializedContractState.fromBytes("v9", state.serialize()),
});

async function fixture(local = false) {
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
  await simulator.ready;
  const initialState = new ContractState();
  initialState.data = simulator.circuitContext.callContext.currentQueryContext.state;
  const queryContractState = vi.fn(async () => networkRead(initialState));
  const readCurrentFinalizedCheckpoint = vi.fn(async () => ({ networkId, blockHash }));
  const makeReader = local ? createLocalCheckpointedDeploymentActionReader : createCheckpointedDeploymentActionReader;
  const reader = makeReader({
    publicDataProvider: { queryContractState } as unknown as Pick<PublicDataProvider, "queryContractState">,
    checkpointSource: { readCurrentFinalizedCheckpoint },
  });
  return { simulator, reader, queryContractState, readCurrentFinalizedCheckpoint };
}

describe("checkpointed deployment action reader", () => {
  it("decodes Compact action state and full deployment state when keyed", async () => {
    const { simulator, reader, queryContractState } = await fixture();
    const ledger = await simulator.getLedger();
    const actionState = await reader.readCurrentFinalizedActionState(`0x${address}`);
    expect(queryContractState).toHaveBeenCalledWith(address, { type: "blockHash", blockHash });
    expect(actionState).toEqual({
      networkId: "preprod",
      finalizedBlockHash: `0x${blockHash}`,
      contractAddress: `0x${address}`,
      registryIdCommitment: bytes32Hex(ledger.registryId),
      deploymentNetworkIdCommitment: bytes32Hex(ledger.deploymentNetworkIdCommitment),
      governancePolicyCommitment: bytes32Hex(ledger.governancePolicyCommitment),
      governanceActionSequence: ledger.governanceActionCount,
    });
    if (!hasRealVerifierKey) return;
    const contractState = new ContractState();
    contractState.data = simulator.circuitContext.callContext.currentQueryContext.state;
    const operation = new ContractOperation();
    const verifierKey = readFileSync(verifierKeyPath);
    operation.verifierKey = verifierKey;
    contractState.setOperation(verifierCircuit, operation);
    contractState.maintenanceAuthority = new ContractMaintenanceAuthority(
      [signatureVerifyingKey(sampleSigningKey())], 1, 0n);
    queryContractState.mockResolvedValue(networkRead(contractState));
    const finalizedLedger = await reader.readCurrentFinalizedLedger(`0x${address}`);
    expect(finalizedLedger).toMatchObject({
      networkId: "preprod",
      finalizedBlockHash: `0x${blockHash}`,
      contractAddress: `0x${address}`,
    });
    if (finalizedLedger === null) throw new Error("Expected a finalized ledger");
    expect(finalizedLedger.ledger.governanceActionCount).toBe(ledger.governanceActionCount);
    expect(bytes32Hex(finalizedLedger.ledger.registryId)).toBe(bytes32Hex(ledger.registryId));
    expect(finalizedLedger.verifierKeySha256).toEqual({
      [verifierCircuit]: createHash("sha256").update(verifierKey).digest("hex"),
    });
    await expect(prepareFinalizedDeploymentActionDigest({
      networkId: "preprod",
      contractAddress: `0x${address}`,
      registryId,
      expectedPolicyCommitment: bytes32Hex(policy),
      expectedActionSequence: ledger.governanceActionCount,
      actionKind: encodeCompactActionKind("tr:epoch:publish"),
      actionPayloadHash: bytes32Commitment("epoch:qualification"),
    }, reader)).resolves.toBeDefined();
  });

  it("reads the complete constructor bootstrap at one finalized block", async () => {
    const { simulator, reader, queryContractState } = await fixture();
    const ledger = await simulator.getLedger();
    const observed = await reader.readCurrentFinalizedBootstrapState(`0x${address}`, bootstrapMaintainerKeyId);
    expect(queryContractState).toHaveBeenCalledTimes(1);
    expect(observed).toMatchObject({
      contractVersion: 1n,
      registryDidCommitment: bytes32Hex(ledger.registryDidCommitment),
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
    const { simulator, reader, queryContractState } = await fixture();
    const verifierKey = readFileSync(verifierKeyPath);
    const operation = new ContractOperation();
    operation.verifierKey = verifierKey;
    const contractState = new ContractState();
    contractState.data = simulator.circuitContext.callContext.currentQueryContext.state;
    contractState.setOperation(verifierCircuit, operation);
    const maintenanceKey = signatureVerifyingKey(sampleSigningKey());
    contractState.maintenanceAuthority = new ContractMaintenanceAuthority([maintenanceKey], 1, 0n);
    queryContractState.mockResolvedValueOnce(networkRead(contractState));

    const observed = await reader.readCurrentFinalizedDeploymentImage(`0x${address}`, bootstrapMaintainerKeyId);
    expect(queryContractState).toHaveBeenCalledTimes(1);
    expect(observed?.finalizedBlockHash).toBe(`0x${blockHash}`);
    expect(observed?.verifierKeySha256).toEqual({
      [verifierCircuit]: createHash("sha256").update(verifierKey).digest("hex"),
    });
    expect(observed?.maintenanceAuthority).toEqual({
      committee: [maintenanceVerifyingKeyHex(maintenanceKey)], threshold: 1, counter: 0n,
    });
    queryContractState.mockResolvedValueOnce(networkRead(contractState));
    const ledgerView = await reader.readCurrentFinalizedLedger(`0x${address}`);
    expect(queryContractState).toHaveBeenCalledTimes(2);
    expect(ledgerView?.verifierKeySha256).toEqual(observed?.verifierKeySha256);
    expect(ledgerView?.maintenanceAuthority).toEqual(observed?.maintenanceAuthority);
  });

  realVerifierKeyIt("returns the local ledger and deployment image from one undeployed checkpoint", async () => {
    const { simulator, reader, queryContractState } = await fixture(true);
    const verifierKey = readFileSync(verifierKeyPath);
    const operation = new ContractOperation();
    operation.verifierKey = verifierKey;
    const state = new ContractState();
    state.data = simulator.circuitContext.callContext.currentQueryContext.state;
    state.setOperation(verifierCircuit, operation);
    const maintenanceKey = signatureVerifyingKey(sampleSigningKey());
    state.maintenanceAuthority = new ContractMaintenanceAuthority([maintenanceKey], 1, 0n);
    queryContractState.mockResolvedValueOnce(networkRead(state));
    const view = await reader.readCurrentFinalizedLedger(`0x${address}`);
    expect(queryContractState).toHaveBeenCalledTimes(1);
    expect(view?.networkId).toBe("undeployed");
    expect(view?.ledger.governanceActionCount).toBe((await simulator.getLedger()).governanceActionCount);
    expect(view?.verifierKeySha256).toEqual({
      [verifierCircuit]: createHash("sha256").update(verifierKey).digest("hex"),
    });
    expect(view?.maintenanceAuthority).toEqual({
      committee: [maintenanceVerifyingKeyHex(maintenanceKey)], threshold: 1, counter: 0n,
    });
  });

  it("fails closed when the checkpoint is absent or malformed", async () => {
    const { reader, readCurrentFinalizedCheckpoint, queryContractState } = await fixture();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toBeNull();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedLedger(`0x${address}`)).resolves.toBeNull();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce({ networkId: "undeployed", blockHash });
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).rejects.toThrow(/malformed/u);
    expect(queryContractState).not.toHaveBeenCalled();
  });

  it("returns no action context when no state exists at the finalized checkpoint", async () => {
    const { reader, queryContractState } = await fixture();
    queryContractState.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toBeNull();
  });

  it("rejects a contract state from an older ledger era", async () => {
    const { reader, queryContractState } = await fixture();
    queryContractState.mockResolvedValueOnce({ contractState: { era: "v8" } } as never);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`))
      .rejects.toThrow(/not Ledger 9/u);
  });

  it("decodes a genesis-pinned local ledger without accepting a public checkpoint", async () => {
    const { reader, simulator, readCurrentFinalizedCheckpoint, queryContractState } = await fixture(true);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toMatchObject({
      networkId: "undeployed",
      deploymentNetworkIdCommitment: bytes32Hex(bytes32Commitment("undeployed")),
    });
    expect(queryContractState).toHaveBeenCalledWith(address, { type: "blockHash", blockHash });
    expect((await simulator.getLedger()).initialized).toBe(true);
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce({ networkId: "preprod", blockHash });
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).rejects.toThrow(/malformed/u);
  });
});
