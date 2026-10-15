import { z } from "zod";

import { EpochCommitmentSchema, type EpochCommitment } from "@midnight-ntwrk/trust-registry-domain";

import {
  GovernedMembershipSignersSchema,
  type GovernedMembershipSigner,
} from "./governed-membership-actions.js";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ScalarSchema = z.string().regex(/^(0|[1-9][0-9]{0,78})$/u);
const LabelSchema = z.string().trim().min(1).max(128);

export const GovernedEpochPrepareRequestSchema = z.strictObject({ label: LabelSchema });

export const PreparedGovernedEpochPublicationSchema = z.strictObject({
  epochId: z.string().min(1),
  registryId: Bytes32Schema,
  networkIdCommitment: Bytes32Schema,
  contractAddress: Bytes32Schema,
  epochIdCommitment: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  stateRoot: Bytes32Schema,
  eventRoot: Bytes32Schema,
  policyRoot: Bytes32Schema,
  validFromSequence: ScalarSchema,
  validUntilSequence: ScalarSchema,
});

export const GovernedEpochPublishRequestSchema = z.strictObject({
  label: LabelSchema,
  prepared: PreparedGovernedEpochPublicationSchema,
  signers: GovernedMembershipSignersSchema,
});

export const GovernedEpochPublicationReceiptSchema = z.strictObject({
  eventHash: Bytes32Schema,
  epoch: EpochCommitmentSchema,
});

export type PreparedGovernedEpochPublication = z.infer<typeof PreparedGovernedEpochPublicationSchema>;
export type GovernedEpochPublishRequest = z.infer<typeof GovernedEpochPublishRequestSchema>;
export type GovernedEpochPublicationReceipt = { eventHash: string; epoch: EpochCommitment };

export type GovernedEpochPublicationContext = {
  epochId: string;
  registryId: Uint8Array;
  networkIdCommitment: Uint8Array;
  contractAddress: Uint8Array;
  epochIdCommitment: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  stateRoot: Uint8Array;
  eventRoot: Uint8Array;
  policyRoot: Uint8Array;
  validFromSequence: bigint;
  validUntilSequence: bigint;
};

export type GovernedEpochPublicationPort = {
  prepare(label: string): Promise<GovernedEpochPublicationContext>;
  execute(label: string, signers: readonly GovernedMembershipSigner[]): Promise<GovernedEpochPublicationReceipt>;
};

export class GovernedEpochPublicationRejectedError extends Error {
  constructor() {
    super("Governed epoch publication rejected");
    this.name = "GovernedEpochPublicationRejectedError";
  }
}

const bytes32Hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Epoch publication context requires bytes32 values");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const serializeGovernedEpochPublication = (
  context: GovernedEpochPublicationContext,
): PreparedGovernedEpochPublication => PreparedGovernedEpochPublicationSchema.parse({
  epochId: context.epochId,
  registryId: bytes32Hex(context.registryId),
  networkIdCommitment: bytes32Hex(context.networkIdCommitment),
  contractAddress: bytes32Hex(context.contractAddress),
  epochIdCommitment: bytes32Hex(context.epochIdCommitment),
  policyCommitment: bytes32Hex(context.policyCommitment),
  actionKind: bytes32Hex(context.actionKind),
  actionPayloadHash: bytes32Hex(context.actionPayloadHash),
  actionSequence: context.actionSequence.toString(),
  stateRoot: bytes32Hex(context.stateRoot),
  eventRoot: bytes32Hex(context.eventRoot),
  policyRoot: bytes32Hex(context.policyRoot),
  validFromSequence: context.validFromSequence.toString(),
  validUntilSequence: context.validUntilSequence.toString(),
});

export const sameGovernedEpochPublication = (
  current: PreparedGovernedEpochPublication,
  submitted: PreparedGovernedEpochPublication,
): boolean => Object.keys(current).every((key) =>
  current[key as keyof PreparedGovernedEpochPublication]
    === submitted[key as keyof PreparedGovernedEpochPublication]);
