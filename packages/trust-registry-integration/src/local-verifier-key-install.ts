import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import {
  InsertVerifierKeyTxFailedError, submitInsertVerifierKeyTx, type ContractProviders,
} from "@midnight-ntwrk/midnight-js-contracts";
import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import type { SigningKey } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import { createVerifierKey, type FinalizedTxData } from "@midnight-ntwrk/midnight-js-types";
import { TrustRegistryContract, type TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";
import { z } from "zod";

import type { FinalizedRegistryDeploymentImage } from "./finalized-deployment-action-reader.js";
import { createLocalNetworkDeploymentActionReader, type LocalNetworkDeploymentActionReaderConfig } from "./local-network-deployment-action-reader.js";
import {
  compiledStagedVerifierKeyContract,
  matchesPinnedRegistryImageWithKeySubset,
  type PublicRegistryBootstrap,
  type PublicRegistryDeploymentReceipt,
  type ReleaseVerifierKeyManifest,
} from "./public-network-deployment.js";
import { readPinnedInstalledVerifierKey } from "./verifier-asset-preflight.js";

type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;
const Hex32 = z.string().regex(/^0x[0-9a-f]{64}$/u);
const Sha256 = z.string().regex(/^[0-9a-f]{64}$/u);
const Revision = z.string().regex(/^[0-9a-f]{40}$/u);
const Reservation = z.strictObject({
  version: z.literal(1),
  networkId: z.literal("undeployed"),
  sourceRevision: Revision,
  expectedGenesisHash: Hex32,
  contractAddress: Hex32,
  finalizedBlockHash: Hex32,
  circuitName: z.string().min(1).max(128),
  verifierKeySha256: Sha256,
  catalogSha256: Sha256,
  installedNames: z.array(z.string().min(1)).min(1),
  currentAuthorityCounter: z.string().regex(/^\d+$/u),
  reservedAt: z.iso.datetime({ offset: false }),
});
const Submitted = z.strictObject({
  version: z.literal(1),
  outcome: z.enum(["succeeded", "failed"]),
  txId: z.string().min(1).max(512),
  blockHash: Hex32,
  blockHeight: z.number().int().nonnegative(),
});

export type LocalVerifierKeyInsertionPlan = Omit<z.infer<typeof Reservation>, "version" | "reservedAt">;
export type LocalVerifierKeyInsertionReceipt = Omit<z.infer<typeof Submitted>, "version">;
export type LocalVerifierKeyInsertionJournalEntry = {
  reservation: z.infer<typeof Reservation>;
  submitted: z.infer<typeof Submitted> | null;
};
export type LocalVerifierKeyInsertionReadback =
  | { status: "verified"; receipt: LocalVerifierKeyInsertionReceipt }
  | { status: "failed-on-chain"; receipt: LocalVerifierKeyInsertionReceipt }
  | { status: "observed-without-receipt" }
  | { status: "pending" }
  | { status: "absent" }
  | { status: "mismatch" };

export class VerifierKeyInsertionAlreadyReservedError extends Error {
  constructor() {
    super("Verifier-key insertion already reserved; reconcile the prior attempt before retrying");
    this.name = "VerifierKeyInsertionAlreadyReservedError";
  }
}

export class VerifierKeyInsertionOutcomeUnknownError extends Error {
  constructor(cause: unknown, readonly receipt?: LocalVerifierKeyInsertionReceipt) {
    super("Verifier-key insertion may have reached the ledger; preserve the journal and inspect finalized state", { cause });
    this.name = "VerifierKeyInsertionOutcomeUnknownError";
  }
}

export class VerifierKeyInsertionJournalInvalidError extends Error {
  constructor(cause: unknown) {
    super("Verifier-key insertion journal is invalid; preserve it for operator recovery", { cause });
    this.name = "VerifierKeyInsertionJournalInvalidError";
  }
}

/** Durable single-host reservation for one circuit update; never auto-retries an unknown result. */
export class FileVerifierKeyInsertionJournal {
  private readonly path: string;

  constructor(path: string) {
    if (!path) throw new Error("Verifier-key insertion journal path is required");
    this.path = resolve(path);
  }

  async inspect(): Promise<LocalVerifierKeyInsertionJournalEntry | null> {
    const reservation = await this.readRecord(this.path, Reservation);
    const submitted = await this.readRecord(`${this.path}.submitted`, Submitted);
    if (reservation === null && submitted !== null) {
      throw new VerifierKeyInsertionJournalInvalidError(new Error("Receipt exists without reservation"));
    }
    return reservation === null ? null : { reservation, submitted };
  }

  async inspectApproved(plan: LocalVerifierKeyInsertionPlan): Promise<LocalVerifierKeyInsertionJournalEntry | null> {
    const entry = await this.inspect();
    if (entry === null) return null;
    const expected = Reservation.parse({ version: 1, ...plan, reservedAt: entry.reservation.reservedAt });
    if (JSON.stringify(entry.reservation) !== JSON.stringify(expected)) {
      throw new VerifierKeyInsertionJournalInvalidError(new Error("Reservation disagrees with approved insertion plan"));
    }
    return entry;
  }

  async executeOnce(
    plan: LocalVerifierKeyInsertionPlan,
    submit: () => Promise<FinalizedTxData>,
  ): Promise<LocalVerifierKeyInsertionReceipt> {
    if (await this.inspect() !== null) throw new VerifierKeyInsertionAlreadyReservedError();
    const reservation = Reservation.parse({ version: 1, ...plan, reservedAt: new Date().toISOString() });
    await this.writeNew(this.path, reservation, true);
    let finalized: FinalizedTxData;
    try {
      finalized = await submit();
    } catch (error) {
      if (error instanceof InsertVerifierKeyTxFailedError) {
        let receipt: LocalVerifierKeyInsertionReceipt;
        try {
          receipt = this.parseReceipt(error.finalizedTxData, "failed");
        } catch (parseError) {
          throw new VerifierKeyInsertionOutcomeUnknownError(parseError);
        }
        try {
          await this.writeNew(`${this.path}.submitted`, { version: 1, ...receipt }, false);
        } catch (writeError) {
          throw new VerifierKeyInsertionOutcomeUnknownError(writeError, receipt);
        }
        throw new VerifierKeyInsertionOutcomeUnknownError(error, receipt);
      }
      throw new VerifierKeyInsertionOutcomeUnknownError(error);
    }
    let receipt: LocalVerifierKeyInsertionReceipt;
    try {
      receipt = this.parseReceipt(finalized, "succeeded");
    } catch (error) {
      throw new VerifierKeyInsertionOutcomeUnknownError(error);
    }
    try {
      await this.writeNew(`${this.path}.submitted`, { version: 1, ...receipt }, false);
    } catch (error) {
      throw new VerifierKeyInsertionOutcomeUnknownError(error, receipt);
    }
    return receipt;
  }

  private parseReceipt(
    finalized: FinalizedTxData,
    outcome: "succeeded" | "failed",
  ): LocalVerifierKeyInsertionReceipt {
    const receipt = {
      outcome,
      txId: finalized.txId,
      blockHash: finalized.blockHash.startsWith("0x")
        ? finalized.blockHash.toLowerCase() : `0x${finalized.blockHash.toLowerCase()}`,
      blockHeight: finalized.blockHeight,
    };
    Submitted.parse({ version: 1, ...receipt });
    return receipt;
  }

  private async readRecord<T>(path: string, schema: z.ZodType<T>): Promise<T | null> {
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw new VerifierKeyInsertionJournalInvalidError(error);
    }
    try {
      const stat = await handle.stat();
      const parent = await lstat(dirname(path));
      if (!parent.isDirectory() || (parent.mode & 0o077) !== 0
        || (process.getuid !== undefined && parent.uid !== process.getuid())
        || !stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size > 32 * 1024
        || (process.getuid !== undefined && stat.uid !== process.getuid())) {
        throw new Error("Verifier-key journal has unsafe file metadata");
      }
      return schema.parse(JSON.parse(await handle.readFile("utf8")));
    } catch (error) {
      throw new VerifierKeyInsertionJournalInvalidError(error);
    } finally {
      await handle.close();
    }
  }

  private async writeNew(path: string, record: object, reservation: boolean): Promise<void> {
    const parent = await lstat(dirname(path));
    if (!parent.isDirectory() || (parent.mode & 0o077) !== 0
      || (process.getuid !== undefined && parent.uid !== process.getuid())) {
      throw new Error("Verifier-key journal directory must be private and locally owned");
    }
    let handle;
    try {
      handle = await open(path, "wx", 0o600);
    } catch (error) {
      if (reservation && (error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new VerifierKeyInsertionAlreadyReservedError();
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

export function planLocalVerifierKeyInsertion(input: {
  network: LocalNetworkDeploymentActionReaderConfig;
  sourceRevision: string;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  bootstrapMaintenanceVerifyingKey: string;
  circuitName: string;
}, image: FinalizedRegistryDeploymentImage): LocalVerifierKeyInsertionPlan {
  if (input.network.networkId !== "undeployed" || getNetworkId() !== "undeployed"
    || input.receipt.networkId !== "undeployed") {
    throw new Error("Verifier-key insertion requires the undeployed local network");
  }
  if (!Revision.safeParse(input.sourceRevision).success
    || !Hex32.safeParse(input.network.expectedGenesisHash).success
    || !Hex32.safeParse(input.receipt.contractAddress).success
    || !Hex32.safeParse(image.finalizedBlockHash).success
    || !Hex32.safeParse(input.bootstrapMaintenanceVerifyingKey).success
    || [input.network.expectedGenesisHash, input.receipt.contractAddress,
      image.finalizedBlockHash, input.bootstrapMaintenanceVerifyingKey]
      .some((value) => /^0x0{64}$/u.test(value))) {
    throw new Error("Verifier-key insertion requires canonical source, genesis, address, and authority pins");
  }
  const installedNames = Object.keys(image.verifierKeySha256).sort();
  const catalogNames = Object.keys(input.releaseManifest.verifierKeySha256).sort();
  if (!catalogNames.includes(input.circuitName) || installedNames.includes(input.circuitName)) {
    throw new Error("Selected verifier key must be absent and present in the release catalog");
  }
  const nextMissing = catalogNames.find((name) => !installedNames.includes(name));
  if (input.circuitName !== nextMissing) {
    throw new Error("Verifier keys must be installed in deterministic release-catalog order");
  }
  if (!matchesPinnedRegistryImageWithKeySubset({
    networkId: "undeployed", receipt: input.receipt, bootstrap: input.bootstrap,
    releaseManifest: input.releaseManifest,
    governance: {
      policyCommitment: input.bootstrap.governancePolicyCommitment,
      policyVersion: 1n, actionSequence: 1n,
      maintainerThreshold: 1n, activeMaintainerCount: 1n,
    },
  }, image, installedNames)
    || image.emergencyMaintainerThreshold !== 1n
    || image.archivalMaintainerThreshold !== 1n) {
    throw new Error("Finalized staged image disagrees with registry or installed key pins");
  }
  if (image.maintenanceAuthority.counter !== BigInt(installedNames.length - 1)
    || image.maintenanceAuthority.threshold !== 1
    || image.maintenanceAuthority.committee.length !== 1
    || image.maintenanceAuthority.committee[0] !== input.bootstrapMaintenanceVerifyingKey) {
    throw new Error("Verifier-key insertion requires the pinned bootstrap maintenance authority");
  }
  const verifierKeySha256 = input.releaseManifest.verifierKeySha256[input.circuitName]!;
  const catalogSha256 = releaseCatalogDigest(input.releaseManifest);
  return {
    networkId: "undeployed", sourceRevision: input.sourceRevision,
    expectedGenesisHash: input.network.expectedGenesisHash,
    contractAddress: input.receipt.contractAddress,
    finalizedBlockHash: image.finalizedBlockHash,
    circuitName: input.circuitName, verifierKeySha256, catalogSha256, installedNames,
    currentAuthorityCounter: image.maintenanceAuthority.counter.toString(),
  };
}

function releaseCatalogDigest(manifest: ReleaseVerifierKeyManifest): string {
  return createHash("sha256").update(JSON.stringify(
    Object.keys(manifest.verifierKeySha256).sort()
      .map((name) => [name, manifest.verifierKeySha256[name]]),
  )).digest("hex");
}

function matchesInsertedImage(input: {
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  bootstrapMaintenanceVerifyingKey: string;
}, plan: LocalVerifierKeyInsertionPlan, image: FinalizedRegistryDeploymentImage): boolean {
  return matchesPinnedRegistryImageWithKeySubset({
    networkId: "undeployed", receipt: input.receipt, bootstrap: input.bootstrap,
    releaseManifest: input.releaseManifest,
    governance: {
      policyCommitment: input.bootstrap.governancePolicyCommitment,
      policyVersion: 1n, actionSequence: 1n,
      maintainerThreshold: 1n, activeMaintainerCount: 1n,
    },
  }, image, [...plan.installedNames, plan.circuitName])
    && image.emergencyMaintainerThreshold === 1n
    && image.archivalMaintainerThreshold === 1n
    && image.maintenanceAuthority.counter === BigInt(plan.currentAuthorityCounter) + 1n
    && image.maintenanceAuthority.threshold === 1
    && image.maintenanceAuthority.committee.length === 1
    && image.maintenanceAuthority.committee[0] === input.bootstrapMaintenanceVerifyingKey;
}

/** Reconciles a reserved attempt from finalized state without submitting or creating a new journal. */
export async function reconcileLocalVerifierKeyInsertion(input: {
  network: LocalNetworkDeploymentActionReaderConfig;
  sourceRevision: string;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  bootstrapMaintenanceVerifyingKey: string;
  circuitName: string;
  journal: FileVerifierKeyInsertionJournal;
}): Promise<LocalVerifierKeyInsertionReadback> {
  if (input.network.networkId !== "undeployed" || getNetworkId() !== "undeployed") {
    throw new Error("Verifier-key reconciliation requires the undeployed local network");
  }
  const entry = await input.journal.inspect();
  if (entry === null) throw new Error("No verifier-key insertion reservation exists");
  const { reservation } = entry;
  if (reservation.networkId !== "undeployed"
    || reservation.sourceRevision !== input.sourceRevision
    || reservation.expectedGenesisHash !== input.network.expectedGenesisHash
    || reservation.contractAddress !== input.receipt.contractAddress
    || reservation.circuitName !== input.circuitName
    || reservation.verifierKeySha256 !== input.releaseManifest.verifierKeySha256[input.circuitName]
    || reservation.catalogSha256 !== releaseCatalogDigest(input.releaseManifest)
    || reservation.currentAuthorityCounter !== BigInt(reservation.installedNames.length - 1).toString()
    || reservation.installedNames.includes(input.circuitName)
    || reservation.installedNames.some((name) => !Object.hasOwn(input.releaseManifest.verifierKeySha256, name))) {
    throw new VerifierKeyInsertionJournalInvalidError(new Error("Reservation disagrees with approved release pins"));
  }
  if (entry.submitted?.outcome === "failed") {
    return { status: "failed-on-chain", receipt: entry.submitted };
  }
  const reader = await createLocalNetworkDeploymentActionReader(input.network);
  const image = await reader.readCurrentFinalizedDeploymentImage(
    input.receipt.contractAddress, input.bootstrap.maintainerKeyId,
  );
  if (image === null || image.finalizedBlockHash === reservation.finalizedBlockHash) {
    return { status: "pending" };
  }
  if (!Object.hasOwn(image.verifierKeySha256, input.circuitName)) {
    return { status: entry.submitted === null ? "absent" : "pending" };
  }
  if (!matchesInsertedImage(input, reservation, image)) return { status: "mismatch" };
  return entry.submitted === null
    ? { status: "observed-without-receipt" }
    : { status: "verified", receipt: entry.submitted };
}

/** Inserts one pinned key only, then independently reads the resulting finalized image. */
export async function submitLocalVerifierKeyInsertion(input: {
  network: LocalNetworkDeploymentActionReaderConfig;
  sourceRevision: string;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  bootstrapMaintenanceVerifyingKey: string;
  circuitName: string;
  journal: FileVerifierKeyInsertionJournal;
  providers: ContractProviders<RegistryContract>;
  contractMaintenanceSigningKey: SigningKey;
}): Promise<{ receipt: LocalVerifierKeyInsertionReceipt; readback: "verified" | "pending" | "absent" | "mismatch" }> {
  const reader = await createLocalNetworkDeploymentActionReader(input.network);
  const before = await reader.readCurrentFinalizedDeploymentImage(
    input.receipt.contractAddress, input.bootstrap.maintainerKeyId,
  );
  if (before === null) throw new Error("Finalized staged image is unavailable");
  const plan = planLocalVerifierKeyInsertion(input, before);
  const key = await readPinnedInstalledVerifierKey(input.releaseManifest, input.circuitName);
  const compiledContract = compiledStagedVerifierKeyContract(input.circuitName);
  const verifierKey = createVerifierKey(key);
  const expectedKey = input.bootstrapMaintenanceVerifyingKey.slice(2);
  if (signatureVerifyingKey(input.contractMaintenanceSigningKey).toLowerCase() !== expectedKey) {
    throw new Error("Insertion signing key disagrees with the pinned bootstrap authority");
  }
  const address = input.receipt.contractAddress.slice(2);
  const priorSigningKey = await input.providers.privateStateProvider.getSigningKey(address);
  if (priorSigningKey !== null
    && signatureVerifyingKey(priorSigningKey).toLowerCase() !== expectedKey) {
    throw new Error("Provider has a different contract maintenance signing key");
  }
  if (priorSigningKey === null) {
    await input.providers.privateStateProvider.setSigningKey(address, input.contractMaintenanceSigningKey);
  }
  const installedSigningKey = await input.providers.privateStateProvider.getSigningKey(address);
  if (installedSigningKey === null
    || signatureVerifyingKey(installedSigningKey).toLowerCase() !== expectedKey) {
    throw new Error("Provider cannot read back the approved maintenance signing key");
  }
  const providerState = await input.providers.publicDataProvider.queryContractState(address);
  if (providerState === null || providerState.operation(input.circuitName) !== undefined
    || providerState.maintenanceAuthority.counter !== BigInt(plan.currentAuthorityCounter)) {
    throw new Error("Provider state disagrees with the finalized key absence or maintenance counter");
  }
  const finalized = await input.journal.executeOnce(plan, () => submitInsertVerifierKeyTx(
    input.providers, compiledContract,
    address,
    input.circuitName as Parameters<typeof submitInsertVerifierKeyTx<RegistryContract>>[3],
    verifierKey,
  ));
  let after: FinalizedRegistryDeploymentImage | null;
  try {
    after = await reader.readCurrentFinalizedDeploymentImage(
      input.receipt.contractAddress, input.bootstrap.maintainerKeyId,
    );
  } catch {
    return { receipt: finalized, readback: "pending" };
  }
  if (after === null || after.finalizedBlockHash === before.finalizedBlockHash) {
    return { receipt: finalized, readback: "pending" };
  }
  if (!Object.hasOwn(after.verifierKeySha256, input.circuitName)) {
    return { receipt: finalized, readback: "pending" };
  }
  return { receipt: finalized, readback: matchesInsertedImage(input, plan, after) ? "verified" : "mismatch" };
}
