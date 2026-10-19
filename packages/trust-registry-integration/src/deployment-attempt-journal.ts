import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import type { ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import type { SigningKey } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import { TrustRegistryContract, trustRegistryWitnesses, type TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";
import { z } from "zod";

import {
  deployLocalTrustRegistry,
  deployPublicTrustRegistry,
  PublicRegistryBootstrap,
  PublicRegistryDeploymentResult,
  ReleaseVerifierKeyManifest,
} from "./public-network-deployment.js";
import type { LocalNetworkDeploymentActionReaderConfig } from "./local-network-deployment-action-reader.js";
import type { PublicNetworkDeploymentActionReaderConfig } from "./public-network-deployment-action-reader.js";

type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;

const Hex32 = z.string().regex(/^0x[0-9a-f]{64}$/u);
const Sha256 = z.string().regex(/^[0-9a-f]{64}$/u);
const Revision = z.string().regex(/^[0-9a-f]{40}$/u);
const Reservation = z.strictObject({
  version: z.literal(1),
  networkId: z.enum(["preview", "preprod", "mainnet", "undeployed"]),
  expectedGenesisHash: Hex32.refine((value) => !/^0x0{64}$/u.test(value)),
  sourceRevision: Revision,
  registryIdCommitment: Hex32,
  bootstrapMaintenanceVerifyingKey: Hex32,
  intentSha256: Sha256,
  reservedAt: z.iso.datetime({ offset: false }),
});
const Submitted = z.strictObject({
  version: z.literal(1),
  networkId: Reservation.shape.networkId,
  contractAddress: Hex32,
  txId: z.string().min(1).max(512),
  blockHash: Hex32,
  blockHeight: z.number().int().nonnegative(),
});

export type DeploymentAttemptJournalEntry = {
  reservation: z.infer<typeof Reservation>;
  submitted: z.infer<typeof Submitted> | null;
};

export type DeploymentAttemptIntent = {
  network: {
    networkId: "preview" | "preprod" | "mainnet" | "undeployed";
    rpcUrl: string;
    indexerHttpUrl: string;
    indexerWsUrl: string;
    expectedGenesisHash: string;
    allowedHosts?: readonly string[];
  };
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  contractMaintenanceSigningKey: SigningKey;
  sourceRevision: string;
};

export class DeploymentAttemptAlreadyReservedError extends Error {
  constructor() {
    super("Deployment attempt already reserved; reconcile the prior attempt before any retry");
    this.name = "DeploymentAttemptAlreadyReservedError";
  }
}

export class DeploymentAttemptOutcomeUnknownError extends Error {
  constructor(cause: unknown, readonly result?: PublicRegistryDeploymentResult) {
    super("Deployment may have reached the network; inspect the journal and finalized state", { cause });
    this.name = "DeploymentAttemptOutcomeUnknownError";
  }
}

export class DeploymentAttemptJournalInvalidError extends Error {
  constructor(cause: unknown) {
    super("Deployment attempt journal is unreadable; preserve it for operator recovery", { cause });
    this.name = "DeploymentAttemptJournalInvalidError";
  }
}

function reservationFor(intent: DeploymentAttemptIntent): z.infer<typeof Reservation> {
  const { network, bootstrap, releaseManifest } = intent;
  if (getNetworkId() !== network.networkId) {
    throw new Error("Midnight.js network does not match the approved deployment network");
  }
  if (!Revision.safeParse(intent.sourceRevision).success
    || !Hex32.safeParse(network.expectedGenesisHash).success
    || /^0x0{64}$/u.test(network.expectedGenesisHash)
    || bootstrap.registryId.length === 0 || bootstrap.registryId.includes("\0")
    || bootstrap.maintainerThreshold !== 1n) {
    throw new Error("Deployment approval has an invalid source, genesis, registry, or bootstrap threshold pin");
  }
  for (const commitment of [
    bootstrap.registryDidCommitment, bootstrap.governancePolicyCommitment,
    bootstrap.maintainerId, bootstrap.maintainerDidCommitment, bootstrap.maintainerKeyId,
  ]) {
    if (commitment.length !== 32 || commitment.every((byte) => byte === 0)) {
      throw new Error("Deployment bootstrap requires nonzero 32-byte commitments");
    }
  }
  if (releaseManifest?.format !== "tr-release-candidate-manifest-v2"
    || !releaseManifest.verifierKeySha256
    || Object.keys(releaseManifest.verifierKeySha256).length === 0) {
    throw new Error("Deployment requires a release verifier-key catalog");
  }
  const verifierKeySha256 = Object.entries(releaseManifest.verifierKeySha256)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  const circuitNames = Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits).sort();
  if (verifierKeySha256.map(([name]) => name).join("\0") !== circuitNames.join("\0")
    || verifierKeySha256.some(([, hash]) => !Sha256.safeParse(hash).success)) {
    throw new Error("Deployment verifier-key catalog is invalid or incomplete");
  }
  const publicIntent = {
    networkId: network.networkId,
    rpcUrl: network.rpcUrl,
    indexerHttpUrl: network.indexerHttpUrl,
    indexerWsUrl: network.indexerWsUrl,
    expectedGenesisHash: network.expectedGenesisHash,
    allowedHosts: [...(network.allowedHosts ?? [])].sort(),
    sourceRevision: intent.sourceRevision,
    registryId: bootstrap.registryId,
    registryDidCommitment: bytes32Hex(bootstrap.registryDidCommitment),
    governancePolicyCommitment: bytes32Hex(bootstrap.governancePolicyCommitment),
    maintainerId: bytes32Hex(bootstrap.maintainerId),
    maintainerDidCommitment: bytes32Hex(bootstrap.maintainerDidCommitment),
    maintainerKeyId: bytes32Hex(bootstrap.maintainerKeyId),
    maintainerPublicKey: {
      x: bootstrap.maintainerPublicKey.x.toString(),
      y: bootstrap.maintainerPublicKey.y.toString(),
    },
    maintainerThreshold: bootstrap.maintainerThreshold.toString(),
    bootstrapMaintenanceVerifyingKey: `0x${signatureVerifyingKey(intent.contractMaintenanceSigningKey).toLowerCase()}`,
    verifierKeySha256,
  };
  return Reservation.parse({
    version: 1,
    networkId: network.networkId,
    expectedGenesisHash: network.expectedGenesisHash,
    sourceRevision: intent.sourceRevision,
    registryIdCommitment: bytes32Hex(bytes32Commitment(bootstrap.registryId)),
    bootstrapMaintenanceVerifyingKey: publicIntent.bootstrapMaintenanceVerifyingKey,
    intentSha256: createHash("sha256").update(JSON.stringify(publicIntent)).digest("hex"),
    reservedAt: new Date().toISOString(),
  });
}

/** Single-host, one-attempt deployment journal. An uncertain outcome is never retried automatically. */
export class FileDeploymentAttemptJournal {
  private readonly path: string;

  constructor(path: string) {
    if (path.length === 0) throw new Error("Deployment attempt journal path is required");
    this.path = resolve(path);
  }

  async inspect(): Promise<DeploymentAttemptJournalEntry | null> {
    const reservation = await this.readRecord(this.path, Reservation);
    const submitted = await this.readRecord(`${this.path}.submitted`, Submitted);
    if (reservation === null && submitted !== null) {
      throw new DeploymentAttemptJournalInvalidError(new Error("Receipt exists without a deployment reservation"));
    }
    if (reservation !== null && submitted !== null && submitted.networkId !== reservation.networkId) {
      throw new DeploymentAttemptJournalInvalidError(new Error("Receipt network disagrees with deployment reservation"));
    }
    return reservation === null ? null : { reservation, submitted };
  }

  async inspectApproved(intent: DeploymentAttemptIntent): Promise<DeploymentAttemptJournalEntry | null> {
    const expected = reservationFor(intent);
    const entry = await this.inspect();
    if (entry !== null && (entry.reservation.networkId !== expected.networkId
      || entry.reservation.expectedGenesisHash !== expected.expectedGenesisHash
      || entry.reservation.sourceRevision !== expected.sourceRevision
      || entry.reservation.registryIdCommitment !== expected.registryIdCommitment
      || entry.reservation.bootstrapMaintenanceVerifyingKey !== expected.bootstrapMaintenanceVerifyingKey
      || entry.reservation.intentSha256 !== expected.intentSha256)) {
      throw new DeploymentAttemptJournalInvalidError(new Error(
        "Deployment reservation disagrees with the independently approved intent",
      ));
    }
    return entry;
  }

  async executeOnce(
    intent: DeploymentAttemptIntent,
    submit: () => Promise<PublicRegistryDeploymentResult>,
  ): Promise<PublicRegistryDeploymentResult> {
    const reservation = reservationFor(intent);
    if (await this.inspect() !== null) throw new DeploymentAttemptAlreadyReservedError();
    await this.writeNew(this.path, reservation, true);
    let result: PublicRegistryDeploymentResult;
    try {
      result = await submit();
    } catch (error) {
      throw new DeploymentAttemptOutcomeUnknownError(error);
    }
    let receipt: z.infer<typeof Submitted>;
    try {
      receipt = Submitted.parse({ version: 1, ...result.receipt });
      if (receipt.networkId !== reservation.networkId) {
        throw new Error("Deployment receipt network disagrees with the reservation");
      }
    } catch (error) {
      throw new DeploymentAttemptOutcomeUnknownError(error, result);
    }
    try {
      await this.writeNew(`${this.path}.submitted`, receipt, false);
    } catch (error) {
      throw new DeploymentAttemptOutcomeUnknownError(error, result);
    }
    return result;
  }

  private async readRecord<T>(path: string, schema: z.ZodType<T>): Promise<T | null> {
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw new DeploymentAttemptJournalInvalidError(error);
    }
    try {
      const stat = await handle.stat();
      const parent = await lstat(dirname(path));
      if (!parent.isDirectory() || (parent.mode & 0o077) !== 0
        || (process.getuid !== undefined && parent.uid !== process.getuid())
        || !stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size > 32 * 1024
        || (process.getuid !== undefined && stat.uid !== process.getuid())) {
        throw new Error("Deployment attempt journal has unsafe file metadata");
      }
      return schema.parse(JSON.parse(await handle.readFile("utf8")));
    } catch (error) {
      throw new DeploymentAttemptJournalInvalidError(error);
    } finally {
      await handle.close();
    }
  }

  private async writeNew(path: string, record: object, reservation: boolean): Promise<void> {
    const parent = await lstat(dirname(path));
    if (!parent.isDirectory() || (parent.mode & 0o077) !== 0
      || (process.getuid !== undefined && parent.uid !== process.getuid())) {
      throw new Error("Deployment attempt journal directory must be private and locally owned");
    }
    let handle;
    try {
      handle = await open(path, "wx", 0o600);
    } catch (error) {
      if (reservation && (error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new DeploymentAttemptAlreadyReservedError();
      }
      throw error;
    }
    try {
      await handle.writeFile(JSON.stringify(record));
      await handle.sync();
    } finally {
      await handle.close();
    }
    const directory = await open(dirname(path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
}

/** Reserve before entering the SDK deployment call; never retry an ambiguous attempt. */
export async function deployPublicTrustRegistryOnce(input: {
  network: PublicNetworkDeploymentActionReaderConfig;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  providers: ContractProviders<RegistryContract>;
  contractMaintenanceSigningKey: SigningKey;
  sourceRevision: string;
  journal: FileDeploymentAttemptJournal;
}): Promise<PublicRegistryDeploymentResult> {
  if ((input.network.networkId as string) === "undeployed") {
    throw new Error("Public deployment journal does not accept the undeployed network");
  }
  return input.journal.executeOnce(input, () => deployPublicTrustRegistry(input));
}

/** Reserve before local deployment; only a genesis-pinned `undeployed` network is accepted. */
export async function deployLocalTrustRegistryOnce(input: {
  network: LocalNetworkDeploymentActionReaderConfig;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  providers: ContractProviders<RegistryContract>;
  contractMaintenanceSigningKey: SigningKey;
  sourceRevision: string;
  journal: FileDeploymentAttemptJournal;
}): Promise<PublicRegistryDeploymentResult> {
  if (input.network.networkId !== "undeployed") {
    throw new Error("Local deployment journal requires the undeployed network");
  }
  return input.journal.executeOnce(input, () => deployLocalTrustRegistry(input));
}
