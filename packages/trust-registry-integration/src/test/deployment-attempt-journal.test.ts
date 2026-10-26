import { mkdtemp, readFile, rm, symlink, chmod, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { sampleSigningKey } from "@midnight-ntwrk/compact-runtime";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import { deriveJubjubPublicKeyFromSeed, TrustRegistryContract, trustRegistryWitnesses } from "@midnight-ntwrk/trust-registry-contract";

import {
  DeploymentAttemptAlreadyReservedError,
  DeploymentAttemptJournalInvalidError,
  DeploymentAttemptOutcomeUnknownError,
  FileDeploymentAttemptJournal,
  deployLocalTrustRegistryOnce,
  deployPublicTrustRegistryOnce,
  type DeploymentAttemptIntent,
} from "../deployment-attempt-journal.js";

const mocks = vi.hoisted(() => ({
  deployPublic: vi.fn(), deployLocal: vi.fn(), verifyInstalledVerifierKeyAssets: vi.fn(),
}));
vi.mock("../public-network-deployment.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../public-network-deployment.js")>(),
  deployPublicTrustRegistry: mocks.deployPublic,
  deployLocalTrustRegistry: mocks.deployLocal,
}));
vi.mock("../verifier-asset-preflight.js", () => ({
  verifyInstalledVerifierKeyAssets: mocks.verifyInstalledVerifierKeyAssets,
}));

const genesis = `0x${"b".repeat(64)}`;
const sourceRevision = "a".repeat(40);
const signingKey = sampleSigningKey();
const bootstrap = {
  registryId: "registry:journal-test",
  registryDidCommitment: bytes32Commitment("did:midnight:preview:registry"),
  governancePolicyCommitment: bytes32Commitment("policy:journal-test"),
  maintainerId: bytes32Commitment("maintainer:journal-test"),
  maintainerDidCommitment: bytes32Commitment("did:midnight:preview:maintainer"),
  maintainerKeyId: bytes32Commitment("maintainer:journal-test#key-1"),
  maintainerPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(23)),
  maintainerThreshold: 1n,
};
const releaseManifest = {
  format: "tr-release-candidate-manifest-v2" as const,
  verifierKeySha256: Object.fromEntries(Object.keys(
    new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits,
  ).map((name) => [name, "c".repeat(64)])),
};
const publicNetwork = {
  networkId: "preview" as const,
  rpcUrl: "https://rpc.example.test/",
  indexerHttpUrl: "https://indexer.example.test/graphql",
  indexerWsUrl: "wss://indexer.example.test/graphql/ws",
  expectedGenesisHash: genesis,
};
const localNetwork = {
  networkId: "undeployed" as const,
  rpcUrl: "http://node:9944",
  indexerHttpUrl: "http://indexer:8080/graphql",
  indexerWsUrl: "ws://indexer:8080/graphql/ws",
  expectedGenesisHash: genesis,
  allowedHosts: ["node", "indexer"],
};
const intent = (): DeploymentAttemptIntent => ({
  network: publicNetwork, bootstrap, releaseManifest,
  contractMaintenanceSigningKey: signingKey, sourceRevision,
});
const result = (networkId = "preview") => ({
  receipt: {
    networkId, contractAddress: `0x${"1".repeat(64)}`, txId: "deployment-tx-id",
    blockHash: `0x${"2".repeat(64)}`, blockHeight: 12,
  },
  readback: { status: "pending" as const },
});
const directories: string[] = [];
const journal = async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-deployment-journal-"));
  directories.push(directory);
  return new FileDeploymentAttemptJournal(join(directory, "deployment.json"));
};

beforeEach(() => {
  vi.clearAllMocks();
  setNetworkId("preview");
});
afterEach(async () => {
  setNetworkId("undeployed");
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("deployment attempt journal", () => {
  it("persists only public intent and receipt, then rejects another attempt", async () => {
    const file = await journal();
    const submit = vi.fn(async () => result());
    await expect(file.executeOnce(intent(), submit)).resolves.toEqual(result());
    const entry = await file.inspectApproved(intent());
    expect(entry?.reservation).toMatchObject({
      networkId: "preview", expectedGenesisHash: genesis, sourceRevision,
      registryIdCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });
    expect(entry?.submitted).toEqual({ version: 1, ...result().receipt });
    const raw = await readFile(join(directories[0]!, "deployment.json"), "utf8");
    expect(raw).not.toContain(JSON.stringify(signingKey));
    await expect(file.executeOnce(intent(), submit)).rejects.toBeInstanceOf(DeploymentAttemptAlreadyReservedError);
    expect(submit).toHaveBeenCalledOnce();
  });

  it("does not retry when submission fails or the receipt is malformed", async () => {
    const file = await journal();
    await expect(file.executeOnce(intent(), async () => { throw new Error("response lost"); }))
      .rejects.toBeInstanceOf(DeploymentAttemptOutcomeUnknownError);
    expect((await file.inspect())?.submitted).toBeNull();
    const retry = vi.fn(async () => result());
    await expect(file.executeOnce(intent(), retry)).rejects.toBeInstanceOf(DeploymentAttemptAlreadyReservedError);
    expect(retry).not.toHaveBeenCalled();

    const malformed = await journal();
    await expect(malformed.executeOnce(intent(), async () => result("preprod")))
      .rejects.toMatchObject({ result: result("preprod") });
    expect((await malformed.inspect())?.submitted).toBeNull();
  });

  it("preserves the returned result when the submitted receipt cannot be written", async () => {
    const file = await journal();
    await expect(file.executeOnce(intent(), async () => {
      await writeFile(join(directories[0]!, "deployment.json.submitted"), "occupied", { mode: 0o600 });
      return result();
    })).rejects.toMatchObject({ result: result() });
    await expect(file.inspect()).rejects.toBeInstanceOf(DeploymentAttemptJournalInvalidError);
  });

  it("allows at most one submit across concurrent journal handles", async () => {
    const file = await journal();
    const other = new FileDeploymentAttemptJournal(join(directories[0]!, "deployment.json"));
    const submit = vi.fn(async () => result());
    const outcomes = await Promise.allSettled([
      file.executeOnce(intent(), submit), other.executeOnce(intent(), submit),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect(submit).toHaveBeenCalledOnce();
  });

  it("rejects changed approval, unsafe files, and network mismatch without submitting", async () => {
    const file = await journal();
    const submit = vi.fn(async () => result());
    await file.executeOnce(intent(), submit);
    await expect(file.inspectApproved({ ...intent(), sourceRevision: "d".repeat(40) }))
      .rejects.toBeInstanceOf(DeploymentAttemptJournalInvalidError);
    await expect(file.inspectApproved({ ...intent(), network: {
      ...publicNetwork, rpcUrl: "https://another-rpc.example.test/",
    } })).rejects.toBeInstanceOf(DeploymentAttemptJournalInvalidError);
    await chmod(join(directories[0]!, "deployment.json"), 0o644);
    await expect(file.inspect()).rejects.toBeInstanceOf(DeploymentAttemptJournalInvalidError);
    const link = await journal();
    await symlink(join(directories[0]!, "deployment.json"), join(directories[1]!, "deployment.json"));
    await expect(link.inspect()).rejects.toBeInstanceOf(DeploymentAttemptJournalInvalidError);
    const fresh = await journal();
    setNetworkId("preprod");
    await expect(fresh.executeOnce(intent(), submit)).rejects.toThrow(/network does not match/u);
    expect(await fresh.inspect()).toBeNull();
    expect(submit).toHaveBeenCalledOnce();
  });

  it("rejects an unsafe parent and orphan or mismatched receipts", async () => {
    const unsafe = await journal();
    await chmod(directories[0]!, 0o755);
    await expect(unsafe.executeOnce(intent(), async () => result())).rejects.toThrow(/private and locally owned/u);
    await chmod(directories[0]!, 0o700);
    await writeFile(join(directories[0]!, "deployment.json.submitted"), JSON.stringify({
      version: 1, ...result().receipt,
    }), { mode: 0o600 });
    await expect(unsafe.inspect()).rejects.toBeInstanceOf(DeploymentAttemptJournalInvalidError);

    const mismatch = await journal();
    await mismatch.executeOnce(intent(), async () => result());
    await rm(join(directories[1]!, "deployment.json.submitted"));
    await writeFile(join(directories[1]!, "deployment.json.submitted"), JSON.stringify({
      version: 1, ...result("preprod").receipt,
    }), { mode: 0o600 });
    await expect(mismatch.inspect()).rejects.toBeInstanceOf(DeploymentAttemptJournalInvalidError);
  });

  it("rejects malformed approval pins before reserving an attempt", async () => {
    const file = await journal();
    const submit = vi.fn(async () => result());
    await expect(file.executeOnce({ ...intent(), sourceRevision: "short" }, submit))
      .rejects.toThrow(/approval has an invalid/u);
    await expect(file.executeOnce({ ...intent(), releaseManifest: {
      ...releaseManifest, verifierKeySha256: { missing: "c".repeat(64) },
    } }, submit)).rejects.toThrow(/catalog is invalid or incomplete/u);
    await expect(file.executeOnce({ ...intent(), bootstrap: {
      ...bootstrap, maintainerId: new Uint8Array(32),
    } }, submit)).rejects.toThrow(/nonzero 32-byte/u);
    expect(await file.inspect()).toBeNull();
    expect(submit).not.toHaveBeenCalled();
  });

  it("routes public and local deployments through distinct guarded wrappers", async () => {
    const publicJournal = await journal();
    mocks.deployPublic.mockResolvedValue(result());
    await expect(deployPublicTrustRegistryOnce({
      ...intent(), providers: {} as never, journal: publicJournal,
      network: { ...publicNetwork, fetchImpl: vi.fn() as never },
    })).resolves.toEqual(result());
    expect(mocks.deployPublic).toHaveBeenCalledOnce();

    setNetworkId("undeployed");
    const localJournal = await journal();
    mocks.deployLocal.mockResolvedValue(result("undeployed"));
    await expect(deployLocalTrustRegistryOnce({
      ...intent(), providers: {} as never, journal: localJournal,
      network: { ...localNetwork, fetchImpl: vi.fn() as never },
    })).resolves.toEqual(result("undeployed"));
    expect(mocks.deployLocal).toHaveBeenCalledOnce();
    await expect(deployPublicTrustRegistryOnce({
      ...intent(), providers: {} as never, journal: await journal(),
      network: { ...localNetwork, fetchImpl: vi.fn() as never } as never,
    })).rejects.toThrow(/does not accept the undeployed/u);
  });

  it("does not reserve a deployment when installed verifier assets disagree", async () => {
    setNetworkId("undeployed");
    const localJournal = await journal();
    mocks.verifyInstalledVerifierKeyAssets.mockRejectedValueOnce(new Error("verifier mismatch"));
    await expect(deployLocalTrustRegistryOnce({
      ...intent(), providers: {} as never, journal: localJournal,
      network: { ...localNetwork, fetchImpl: vi.fn() as never },
    })).rejects.toThrow(/verifier mismatch/u);
    expect(await localJournal.inspect()).toBeNull();
    expect(mocks.deployLocal).not.toHaveBeenCalled();
  });
});
