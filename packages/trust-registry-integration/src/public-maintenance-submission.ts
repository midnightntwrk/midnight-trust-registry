import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { submitTxAsync, type ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import type { Signature } from "@midnight-ntwrk/midnight-js-protocol/ledger";
import { z } from "zod";
import { TrustRegistryContract, type TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";

import {
  preparePublicNetworkCommitteeTransition,
  type CommitteeTransitionApproval,
  type PreparedCommitteeTransition,
} from "./public-maintenance-transition.js";

type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;

const Hex32 = z.string().regex(/^0x[0-9a-f]{64}$/u);
const Reservation = z.strictObject({
  version: z.literal(1),
  networkId: z.string().min(1).max(128),
  contractAddress: Hex32,
  finalizedBlockHash: Hex32,
  currentAuthorityCounter: z.string().regex(/^\d+$/u),
  nextAuthorityCounter: z.string().regex(/^\d+$/u),
  committeeVerifyingKeys: z.array(Hex32).min(3).max(128),
  threshold: z.number().int().min(2),
  updateSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  expiresAt: z.iso.datetime({ offset: false }),
  reservedAt: z.iso.datetime({ offset: false }),
}).refine((value) => value.threshold <= value.committeeVerifyingKeys.length);
const Submitted = z.strictObject({
  version: z.literal(1),
  txId: z.string().min(1).max(512),
});

export type MaintenanceTransitionJournalEntry = {
  reservation: z.infer<typeof Reservation>;
  submitted: z.infer<typeof Submitted> | null;
};

export class MaintenanceTransitionAlreadyReservedError extends Error {
  constructor() {
    super("Maintenance transition already reserved; reconcile the prior attempt before any retry");
    this.name = "MaintenanceTransitionAlreadyReservedError";
  }
}

export class MaintenanceTransitionOutcomeUnknownError extends Error {
  constructor(cause: unknown, readonly txId?: string) {
    super("Maintenance transition may have reached the network; inspect the journal and finalized state", { cause });
    this.name = "MaintenanceTransitionOutcomeUnknownError";
  }
}

export class MaintenanceTransitionJournalInvalidError extends Error {
  constructor(cause: unknown) {
    super("Maintenance transition journal is unreadable; preserve it for operator recovery, do not delete it", { cause });
    this.name = "MaintenanceTransitionJournalInvalidError";
  }
}

/** One durable, single-host attempt per deployment. A reserved attempt is never automatically retried. */
export class FileMaintenanceTransitionJournal {
  private readonly path: string;

  constructor(path: string) {
    if (path.length === 0) throw new Error("Maintenance transition journal path is required");
    this.path = resolve(path);
  }

  async inspect(): Promise<MaintenanceTransitionJournalEntry | null> {
    const reservation = await this.readRecord(this.path, Reservation);
    const submitted = await this.readRecord(`${this.path}.submitted`, Submitted);
    if (reservation === null && submitted !== null) {
      throw new Error("Submitted transaction exists without its maintenance reservation");
    }
    return reservation === null ? null : { reservation, submitted };
  }

  async executeOnce(plan: PreparedCommitteeTransition, submit: () => Promise<string>): Promise<string> {
    if (await this.inspect() !== null) throw new MaintenanceTransitionAlreadyReservedError();
    const reservation = Reservation.parse({
      version: 1,
      networkId: plan.networkId,
      contractAddress: plan.contractAddress,
      finalizedBlockHash: plan.finalizedBlockHash,
      currentAuthorityCounter: plan.currentAuthorityCounter.toString(),
      nextAuthorityCounter: plan.nextAuthorityCounter.toString(),
      committeeVerifyingKeys: [...plan.committeeVerifyingKeys],
      threshold: plan.threshold,
      updateSha256: createHash("sha256").update(plan.dataToSign).digest("hex"),
      expiresAt: plan.expiresAt,
      reservedAt: new Date().toISOString(),
    });
    await this.writeNew(this.path, reservation, true);
    let returned: unknown;
    try {
      returned = await submit();
    } catch (error) {
      throw new MaintenanceTransitionOutcomeUnknownError(error);
    }
    let txId: string;
    try {
      txId = Submitted.shape.txId.parse(returned);
    } catch (error) {
      throw new MaintenanceTransitionOutcomeUnknownError(error, typeof returned === "string" ? returned : undefined);
    }
    try {
      await this.writeNew(`${this.path}.submitted`, Submitted.parse({ version: 1, txId }), false);
    } catch (error) {
      throw new MaintenanceTransitionOutcomeUnknownError(error, txId);
    }
    return txId;
  }

  private async readRecord<T>(path: string, schema: z.ZodType<T>): Promise<T | null> {
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    try {
      const stat = await handle.stat();
      const parent = await lstat(dirname(path));
      if (!parent.isDirectory() || (parent.mode & 0o077) !== 0
        || (process.getuid !== undefined && parent.uid !== process.getuid())
        || !stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size > 32 * 1024
        || (process.getuid !== undefined && stat.uid !== process.getuid())) {
        throw new Error("Maintenance transition journal has unsafe file metadata");
      }
      try {
        return schema.parse(JSON.parse(await handle.readFile("utf8")));
      } catch (error) {
        throw new MaintenanceTransitionJournalInvalidError(error);
      }
    } finally {
      await handle.close();
    }
  }

  private async writeNew(path: string, record: object, reservation: boolean): Promise<void> {
    const parent = await lstat(dirname(path));
    if (!parent.isDirectory() || (parent.mode & 0o077) !== 0
      || (process.getuid !== undefined && parent.uid !== process.getuid())) {
      throw new Error("Maintenance transition journal directory must be private and locally owned");
    }
    let handle;
    try {
      handle = await open(path, "wx", 0o600);
    } catch (error) {
      if (reservation && (error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new MaintenanceTransitionAlreadyReservedError();
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

/** Re-reads finalized state, verifies the external signature, reserves, then submits once. */
export async function submitPublicNetworkCommitteeTransition(input: {
  approval: CommitteeTransitionApproval;
  signature: Signature;
  journal: FileMaintenanceTransitionJournal;
  providers: ContractProviders<RegistryContract>;
}): Promise<string> {
  const plan = await preparePublicNetworkCommitteeTransition(input.approval);
  const tx = plan.authorize(input.signature);
  return input.journal.executeOnce(plan, () => submitTxAsync(input.providers, { unprovenTx: tx }));
}
