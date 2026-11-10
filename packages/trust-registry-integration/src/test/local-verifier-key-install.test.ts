import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { InsertVerifierKeyTxFailedError } from "@midnight-ntwrk/midnight-js-contracts";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import {
  deriveJubjubPublicKeyFromSeed, MaintainerStatus,
  TrustRegistryContract, trustRegistryWitnesses,
} from "@midnight-ntwrk/trust-registry-contract";

import type { FinalizedRegistryDeploymentImage } from "../finalized-deployment-action-reader.js";
import {
  FileVerifierKeyInsertionJournal,
  VerifierKeyInsertionAlreadyReservedError,
  VerifierKeyInsertionJournalInvalidError,
  VerifierKeyInsertionOutcomeUnknownError,
  planLocalVerifierKeyInsertion,
  reconcileLocalVerifierKeyInsertion,
  submitLocalVerifierKeyInsertion,
} from "../local-verifier-key-install.js";

const mocks = vi.hoisted(() => ({
  readImage: vi.fn(), readPinnedKey: vi.fn(), submitInsert: vi.fn(), compiledContract: vi.fn(),
}));
vi.mock("../public-network-deployment.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../public-network-deployment.js")>(),
  compiledStagedVerifierKeyContract: mocks.compiledContract,
}));
vi.mock("../local-network-deployment-action-reader.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../local-network-deployment-action-reader.js")>(),
  createLocalNetworkDeploymentActionReader: vi.fn(async () => ({
    readCurrentFinalizedDeploymentImage: mocks.readImage,
  })),
}));
vi.mock("../verifier-asset-preflight.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../verifier-asset-preflight.js")>(),
  readPinnedInstalledVerifierKey: mocks.readPinnedKey,
}));
vi.mock("@midnight-ntwrk/midnight-js-contracts", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/midnight-js-contracts")>(),
  submitInsertVerifierKeyTx: mocks.submitInsert,
}));

const sourceRevision = "a".repeat(40);
const genesis = `0x${"b".repeat(64)}`;
const address = `0x${"c".repeat(64)}`;
const signingKey = sampleSigningKey();
const bootstrapKey = `0x${signatureVerifyingKey(signingKey).toLowerCase()}`;
const network = {
  networkId: "undeployed" as const,
  rpcUrl: "http://node:9944",
  indexerHttpUrl: "http://indexer:8080/graphql",
  indexerWsUrl: "ws://indexer:8080/graphql/ws",
  expectedGenesisHash: genesis,
  allowedHosts: ["node", "indexer"],
};
const bootstrap = {
  registryId: "registry:staged-test",
  registryDidCommitment: bytes32Commitment("did:midnight:undeployed:registry"),
  governancePolicyCommitment: bytes32Commitment("policy:staged-test"),
  maintainerId: bytes32Commitment("maintainer:staged-test"),
  maintainerDidCommitment: bytes32Commitment("did:midnight:undeployed:maintainer"),
  maintainerKeyId: bytes32Commitment("maintainer:staged-test#key-1"),
  maintainerPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(31)),
  maintainerThreshold: 1n,
};
const names = Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits).sort();
const releaseManifest = {
  format: "tr-release-candidate-manifest-v2" as const,
  verifierKeySha256: Object.fromEntries(names.map((name) => [
    name, createHash("sha256").update(`verifier:${name}`).digest("hex"),
  ])),
};
const receipt = {
  networkId: "undeployed", contractAddress: address,
  txId: "deploy-tx", blockHash: `0x${"e".repeat(64)}`, blockHeight: 10,
};
const input = () => ({
  network, sourceRevision, receipt, bootstrap, releaseManifest,
  bootstrapMaintenanceVerifyingKey: bootstrapKey,
  circuitName: names[1]!,
  contractMaintenanceSigningKey: signingKey,
});
const providers = () => {
  let stored: typeof signingKey | null = null;
  return {
    privateStateProvider: {
      getSigningKey: vi.fn(async () => stored),
      setSigningKey: vi.fn(async (_address: string, key: typeof signingKey) => { stored = key; }),
    },
    publicDataProvider: {
      queryContractState: vi.fn(async () => ({
        operation: () => undefined,
        maintenanceAuthority: { counter: 0n },
      })),
    },
  } as never;
};
const image = (): FinalizedRegistryDeploymentImage => ({
  networkId: "undeployed",
  finalizedBlockHash: `0x${"f".repeat(64)}`,
  contractAddress: address,
  registryIdCommitment: bytes32Hex(bytes32Commitment(bootstrap.registryId)),
  deploymentNetworkIdCommitment: bytes32Hex(bytes32Commitment("undeployed")),
  governancePolicyCommitment: bytes32Hex(bootstrap.governancePolicyCommitment),
  governancePolicyVersion: 1n,
  governanceActionSequence: 1n,
  contractVersion: 1n,
  registryDidCommitment: bytes32Hex(bootstrap.registryDidCommitment),
  maintainerThreshold: 1n,
  emergencyMaintainerThreshold: 1n,
  archivalMaintainerThreshold: 1n,
  activeMaintainerCount: 1n,
  bootstrapMaintainer: {
    maintainerId: bytes32Hex(bootstrap.maintainerId),
    didCommitment: bytes32Hex(bootstrap.maintainerDidCommitment),
    keyId: bytes32Hex(bootstrap.maintainerKeyId),
    publicKey: bootstrap.maintainerPublicKey,
    status: MaintainerStatus.active,
    joinedAtSequence: 0n,
  },
  verifierKeySha256: { [names[0]!]: releaseManifest.verifierKeySha256[names[0]!]! },
  maintenanceAuthority: { committee: [bootstrapKey], threshold: 1, counter: 0n },
});
const directories: string[] = [];
const journal = async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-verifier-insert-"));
  directories.push(directory);
  return new FileVerifierKeyInsertionJournal(join(directory, "attempt.json"));
};

beforeEach(() => {
  setNetworkId("undeployed");
  vi.clearAllMocks();
  mocks.compiledContract.mockReturnValue({ circuit: "key" });
});
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("local verifier-key insertion", () => {
  it("plans a single absent catalog key from the pinned finalized image", () => {
    const plan = planLocalVerifierKeyInsertion(input(), image());
    expect(plan).toMatchObject({
      networkId: "undeployed", contractAddress: address,
      circuitName: names[1], installedNames: [names[0]],
      verifierKeySha256: releaseManifest.verifierKeySha256[names[1]!],
    });
    expect(plan.catalogSha256).toMatch(/^[0-9a-f]{64}$/u);
    const twoInstalled = {
      ...image(),
      verifierKeySha256: {
        ...image().verifierKeySha256,
        [names[1]!]: releaseManifest.verifierKeySha256[names[1]!]!,
      },
      maintenanceAuthority: { ...image().maintenanceAuthority, counter: 1n },
    };
    expect(planLocalVerifierKeyInsertion({ ...input(), circuitName: names[2]! }, twoInstalled))
      .toMatchObject({ currentAuthorityCounter: "1", installedNames: names.slice(0, 2) });
  });

  it("rejects unexpected, changed, or already-installed on-chain keys", () => {
    expect(() => planLocalVerifierKeyInsertion(input(), {
      ...image(), verifierKeySha256: { [names[0]!]: "0".repeat(64) },
    })).toThrow(/disagrees/u);
    expect(() => planLocalVerifierKeyInsertion(input(), {
      ...image(), verifierKeySha256: { ...image().verifierKeySha256, surprise: "a".repeat(64) },
    })).toThrow(/disagrees/u);
    expect(() => planLocalVerifierKeyInsertion(input(), {
      ...image(), verifierKeySha256: {
        ...image().verifierKeySha256, [names[1]!]: releaseManifest.verifierKeySha256[names[1]!]!,
      },
    })).toThrow(/must be absent/u);
    expect(() => planLocalVerifierKeyInsertion({ ...input(), circuitName: "notInCatalog" }, image()))
      .toThrow(/release catalog/u);
    expect(() => planLocalVerifierKeyInsertion({ ...input(), circuitName: names[2]! }, image()))
      .toThrow(/deterministic release-catalog order/u);
  });

  it("rejects changed authority, governance, and network pins", () => {
    expect(() => planLocalVerifierKeyInsertion(input(), {
      ...image(), maintenanceAuthority: { committee: [bootstrapKey], threshold: 2, counter: 0n },
    })).toThrow(/bootstrap maintenance authority/u);
    expect(() => planLocalVerifierKeyInsertion(input(), {
      ...image(), governanceActionSequence: 2n,
    })).toThrow(/disagrees/u);
    expect(() => planLocalVerifierKeyInsertion(input(), {
      ...image(), emergencyMaintainerThreshold: 2n,
    })).toThrow(/disagrees/u);
    expect(() => planLocalVerifierKeyInsertion({ ...input(), network: {
      ...network, networkId: "preprod" as never,
    } }, image())).toThrow(/undeployed/u);
  });

  it("reserves once, stores only public receipt, and rejects changed approval", async () => {
    const file = await journal();
    const plan = planLocalVerifierKeyInsertion(input(), image());
    const submit = vi.fn(async () => ({
      txId: "insert-tx", blockHash: "1".repeat(64), blockHeight: 21,
    }) as never);
    await expect(file.executeOnce(plan, submit)).resolves.toEqual({
      outcome: "succeeded", txId: "insert-tx", blockHash: `0x${"1".repeat(64)}`, blockHeight: 21,
    });
    await expect(file.inspectApproved(plan)).resolves.not.toBeNull();
    await expect(file.inspectApproved({ ...plan, circuitName: names[2]! }))
      .rejects.toBeInstanceOf(VerifierKeyInsertionJournalInvalidError);
    await expect(file.executeOnce(plan, submit))
      .rejects.toBeInstanceOf(VerifierKeyInsertionAlreadyReservedError);
    expect(submit).toHaveBeenCalledOnce();
    expect(await readFile(join(directories[0]!, "attempt.json"), "utf8"))
      .not.toContain("private");
  });

  it("retains an ambiguous reservation and rejects unsafe journal metadata", async () => {
    const file = await journal();
    const plan = planLocalVerifierKeyInsertion(input(), image());
    await expect(file.executeOnce(plan, async () => { throw new Error("connection lost"); }))
      .rejects.toBeInstanceOf(VerifierKeyInsertionOutcomeUnknownError);
    expect((await file.inspect())?.submitted).toBeNull();
    const retry = vi.fn();
    await expect(file.executeOnce(plan, retry))
      .rejects.toBeInstanceOf(VerifierKeyInsertionAlreadyReservedError);
    expect(retry).not.toHaveBeenCalled();
    await chmod(join(directories[0]!, "attempt.json"), 0o644);
    await expect(file.inspect()).rejects.toBeInstanceOf(VerifierKeyInsertionJournalInvalidError);
    const link = await journal();
    await symlink(join(directories[0]!, "attempt.json"), join(directories[1]!, "attempt.json"));
    await expect(link.inspect()).rejects.toBeInstanceOf(VerifierKeyInsertionJournalInvalidError);
  });

  it("retains a finalized failed update receipt without permitting a retry", async () => {
    const file = await journal();
    const plan = planLocalVerifierKeyInsertion(input(), image());
    const finalized = { txId: "failed-tx", blockHash: "2".repeat(64), blockHeight: 22 };
    await expect(file.executeOnce(plan, async () => {
      throw new InsertVerifierKeyTxFailedError(finalized as never);
    })).rejects.toMatchObject({
      receipt: { outcome: "failed", txId: "failed-tx", blockHash: `0x${"2".repeat(64)}` },
    });
    expect((await file.inspect())?.submitted?.outcome).toBe("failed");
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: file }))
      .resolves.toMatchObject({ status: "failed-on-chain", receipt: { txId: "failed-tx" } });
    await expect(file.executeOnce(plan, async () => finalized as never))
      .rejects.toBeInstanceOf(VerifierKeyInsertionAlreadyReservedError);
  });

  it("checks pinned inputs before reservation and verifies only a subsequent finalized image", async () => {
    const file = await journal();
    const before = image();
    const after = {
      ...before,
      finalizedBlockHash: `0x${"1".repeat(64)}`,
      verifierKeySha256: {
        ...before.verifierKeySha256,
        [names[1]!]: releaseManifest.verifierKeySha256[names[1]!]!,
      },
      maintenanceAuthority: { ...before.maintenanceAuthority, counter: 1n },
    };
    mocks.readImage.mockResolvedValueOnce(before).mockResolvedValueOnce(after);
    mocks.readPinnedKey.mockResolvedValue(new Uint8Array([1, 2, 3]));
    mocks.submitInsert.mockImplementation(async () => {
      expect((await file.inspect())?.reservation.circuitName).toBe(names[1]);
      return { txId: "insert-tx", blockHash: "1".repeat(64), blockHeight: 21 };
    });
    const outcome = await submitLocalVerifierKeyInsertion({
      ...input(), journal: file, providers: providers(),
    });
    expect(outcome.readback).toBe("verified");
    expect((await file.inspect())?.submitted?.txId).toBe("insert-tx");
    expect(mocks.readPinnedKey).toHaveBeenCalledWith(releaseManifest, names[1]);
    expect(mocks.submitInsert).toHaveBeenCalledOnce();
    expect(mocks.submitInsert.mock.calls[0]?.[2]).toBe(address.slice(2));
    expect(mocks.submitInsert.mock.calls[0]?.[3]).toBe(names[1]);
  });

  it("does not reserve when key bytes fail preflight and reports lagging readback as pending", async () => {
    const failed = await journal();
    mocks.readImage.mockResolvedValue(image());
    mocks.readPinnedKey.mockRejectedValueOnce(new Error("asset mismatch"));
    await expect(submitLocalVerifierKeyInsertion({
      ...input(), journal: failed, providers: providers(),
    })).rejects.toThrow(/asset mismatch/u);
    expect(await failed.inspect()).toBeNull();
    expect(mocks.submitInsert).not.toHaveBeenCalled();

    const pending = await journal();
    mocks.readPinnedKey.mockResolvedValue(new Uint8Array([1, 2, 3]));
    mocks.submitInsert.mockResolvedValue({
      txId: "insert-tx", blockHash: "1".repeat(64), blockHeight: 21,
    });
    const outcome = await submitLocalVerifierKeyInsertion({
      ...input(), journal: pending, providers: providers(),
    });
    expect(outcome.readback).toBe("pending");
    expect((await pending.inspect())?.submitted?.txId).toBe("insert-tx");
  });

  it("does not reserve or install a signing key when compiled contract preparation fails", async () => {
    const file = await journal();
    const provider = providers() as unknown as {
      privateStateProvider: { setSigningKey: ReturnType<typeof vi.fn> };
    };
    mocks.readImage.mockResolvedValue(image());
    mocks.readPinnedKey.mockResolvedValue(new Uint8Array([1, 2, 3]));
    mocks.compiledContract.mockImplementationOnce(() => { throw new Error("compiled circuit unavailable"); });

    await expect(submitLocalVerifierKeyInsertion({
      ...input(), journal: file, providers: provider as never,
    })).rejects.toThrow(/compiled circuit unavailable/u);
    expect(await file.inspect()).toBeNull();
    expect(provider.privateStateProvider.setSigningKey).not.toHaveBeenCalled();
    expect(mocks.submitInsert).not.toHaveBeenCalled();
  });

  it("rejects missing or mismatched signing keys before journal reservation", async () => {
    const wrong = await journal();
    mocks.readImage.mockResolvedValue(image());
    mocks.readPinnedKey.mockResolvedValue(new Uint8Array([1, 2, 3]));
    await expect(submitLocalVerifierKeyInsertion({
      ...input(), contractMaintenanceSigningKey: sampleSigningKey(),
      journal: wrong, providers: providers(),
    })).rejects.toThrow(/disagrees with the pinned bootstrap authority/u);
    expect(await wrong.inspect()).toBeNull();

    const unreadable = await journal();
    const badProviders = {
      privateStateProvider: {
        getSigningKey: async () => null,
        setSigningKey: async () => {},
      },
      publicDataProvider: { queryContractState: async () => ({ operation: () => undefined }) },
    };
    await expect(submitLocalVerifierKeyInsertion({
      ...input(), journal: unreadable, providers: badProviders as never,
    })).rejects.toThrow(/cannot read back/u);
    expect(await unreadable.inspect()).toBeNull();
    expect(mocks.submitInsert).not.toHaveBeenCalled();
  });

  it("rejects a stale indexer maintenance counter before reservation", async () => {
    const file = await journal();
    mocks.readImage.mockResolvedValue(image());
    mocks.readPinnedKey.mockResolvedValue(new Uint8Array([1, 2, 3]));
    const stale = providers() as unknown as {
      publicDataProvider: { queryContractState: ReturnType<typeof vi.fn> };
    };
    stale.publicDataProvider.queryContractState.mockResolvedValue({
      operation: () => undefined,
      maintenanceAuthority: { counter: 1n },
    });
    await expect(submitLocalVerifierKeyInsertion({
      ...input(), journal: file, providers: stale as never,
    })).rejects.toThrow(/maintenance counter/u);
    expect(await file.inspect()).toBeNull();
    expect(mocks.submitInsert).not.toHaveBeenCalled();
  });

  it("reconciles a finalized key without resubmission and flags missing receipts", async () => {
    const file = await journal();
    const plan = planLocalVerifierKeyInsertion(input(), image());
    await expect(file.executeOnce(plan, async () => { throw new Error("watch interrupted"); }))
      .rejects.toBeInstanceOf(VerifierKeyInsertionOutcomeUnknownError);
    const after = {
      ...image(), finalizedBlockHash: `0x${"1".repeat(64)}`,
      verifierKeySha256: {
        ...image().verifierKeySha256,
        [names[1]!]: releaseManifest.verifierKeySha256[names[1]!]!,
      },
      maintenanceAuthority: { ...image().maintenanceAuthority, counter: 1n },
    };
    mocks.readImage.mockResolvedValue(after);
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: file }))
      .resolves.toEqual({ status: "observed-without-receipt" });
    expect(mocks.submitInsert).not.toHaveBeenCalled();
    mocks.readImage.mockResolvedValue({ ...image(), finalizedBlockHash: `0x${"1".repeat(64)}` });
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: file }))
      .resolves.toEqual({ status: "absent" });
    mocks.readImage.mockResolvedValue({ ...after, verifierKeySha256: {
      ...after.verifierKeySha256, [names[1]!]: "0".repeat(64),
    } });
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: file }))
      .resolves.toEqual({ status: "mismatch" });
    mocks.readImage.mockResolvedValue({ ...image(), finalizedBlockHash: plan.finalizedBlockHash });
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: file }))
      .resolves.toEqual({ status: "pending" });
    await expect(reconcileLocalVerifierKeyInsertion({
      ...input(), circuitName: names[2]!, journal: file,
    })).rejects.toBeInstanceOf(VerifierKeyInsertionJournalInvalidError);
    const missing = await journal();
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: missing }))
      .rejects.toThrow(/No verifier-key insertion reservation/u);
  });

  it("recognizes a successful submitted receipt only after its key is finalized", async () => {
    const file = await journal();
    const plan = planLocalVerifierKeyInsertion(input(), image());
    await file.executeOnce(plan, async () => ({
      txId: "insert-tx", blockHash: "1".repeat(64), blockHeight: 21,
    }) as never);
    mocks.readImage.mockResolvedValue({ ...image(), finalizedBlockHash: `0x${"1".repeat(64)}` });
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: file }))
      .resolves.toEqual({ status: "pending" });
    mocks.readImage.mockResolvedValue({
      ...image(), finalizedBlockHash: `0x${"1".repeat(64)}`,
      verifierKeySha256: {
        ...image().verifierKeySha256,
        [names[1]!]: releaseManifest.verifierKeySha256[names[1]!]!,
      },
      maintenanceAuthority: { ...image().maintenanceAuthority, counter: 1n },
    });
    await expect(reconcileLocalVerifierKeyInsertion({ ...input(), journal: file }))
      .resolves.toMatchObject({ status: "verified", receipt: { txId: "insert-tx" } });
  });
});
