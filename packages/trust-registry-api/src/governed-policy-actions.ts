import { z } from "zod";

import {
  GovernedMembershipSignersSchema,
  type GovernedMembershipSigner,
} from "./governed-membership-actions.js";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ScalarSchema = z.string().regex(/^(0|[1-9][0-9]{0,78})$/u);

export const GovernedThresholdsSchema = z.strictObject({
  default: ScalarSchema,
  emergency: ScalarSchema,
  archival: ScalarSchema,
});

export const GovernedThresholdPrepareRequestSchema = z.strictObject({
  thresholds: GovernedThresholdsSchema,
});

export const PreparedGovernedPolicyActionSchema = z.strictObject({
  registryId: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  nextPolicyCommitment: Bytes32Schema.optional(),
  nextPolicyVersion: ScalarSchema.optional(),
  authorizationId: Bytes32Schema.optional(),
  keyIdCommitment: Bytes32Schema.optional(),
  policyVersion: ScalarSchema.optional(),
});

export const GovernedThresholdSubmitRequestSchema = GovernedThresholdPrepareRequestSchema.extend({
  prepared: PreparedGovernedPolicyActionSchema,
  signers: GovernedMembershipSignersSchema,
});

export const GovernedEvidenceVerifierPrepareRequestSchema = z.strictObject({});
export const GovernedEvidenceVerifierSubmitRequestSchema = z.strictObject({
  prepared: PreparedGovernedPolicyActionSchema,
  signers: GovernedMembershipSignersSchema,
});

export const GovernedPolicyActionReceiptSchema = z.strictObject({ eventHash: Bytes32Schema });

export type GovernedThresholds = z.infer<typeof GovernedThresholdsSchema>;
export type PreparedGovernedPolicyAction = z.infer<typeof PreparedGovernedPolicyActionSchema>;
export type GovernedThresholdSubmitRequest = z.infer<typeof GovernedThresholdSubmitRequestSchema>;
export type GovernedEvidenceVerifierSubmitRequest = z.infer<typeof GovernedEvidenceVerifierSubmitRequestSchema>;
export type GovernedPolicyActionReceipt = z.infer<typeof GovernedPolicyActionReceiptSchema>;

export type GovernedPolicyActionContext = {
  registryId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  nextPolicyCommitment?: Uint8Array;
  nextPolicyVersion?: bigint;
  authorizationId?: Uint8Array;
  keyIdCommitment?: Uint8Array;
  policyVersion?: bigint;
};

export type GovernedPolicyActionPort = {
  prepareThresholds(thresholds: GovernedThresholds): Promise<GovernedPolicyActionContext>;
  executeThresholds(
    thresholds: GovernedThresholds,
    signers: readonly GovernedMembershipSigner[],
  ): Promise<GovernedPolicyActionReceipt>;
  prepareEvidenceVerifier(): Promise<GovernedPolicyActionContext>;
  executeEvidenceVerifier(signers: readonly GovernedMembershipSigner[]): Promise<GovernedPolicyActionReceipt>;
};

export class GovernedPolicyActionRejectedError extends Error {
  constructor() {
    super("Governed policy action rejected");
    this.name = "GovernedPolicyActionRejectedError";
  }
}

const bytes32Hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Governed policy context requires bytes32 values");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const serializeGovernedPolicyAction = (
  context: GovernedPolicyActionContext,
): PreparedGovernedPolicyAction => PreparedGovernedPolicyActionSchema.parse({
  registryId: bytes32Hex(context.registryId),
  policyCommitment: bytes32Hex(context.policyCommitment),
  actionKind: bytes32Hex(context.actionKind),
  actionPayloadHash: bytes32Hex(context.actionPayloadHash),
  actionSequence: context.actionSequence.toString(),
  ...(context.nextPolicyCommitment === undefined ? {} : {
    nextPolicyCommitment: bytes32Hex(context.nextPolicyCommitment),
  }),
  ...(context.nextPolicyVersion === undefined ? {} : {
    nextPolicyVersion: context.nextPolicyVersion.toString(),
  }),
  ...(context.authorizationId === undefined ? {} : {
    authorizationId: bytes32Hex(context.authorizationId),
  }),
  ...(context.keyIdCommitment === undefined ? {} : {
    keyIdCommitment: bytes32Hex(context.keyIdCommitment),
  }),
  ...(context.policyVersion === undefined ? {} : {
    policyVersion: context.policyVersion.toString(),
  }),
});

export const sameGovernedPolicyAction = (
  current: PreparedGovernedPolicyAction,
  submitted: PreparedGovernedPolicyAction,
): boolean => JSON.stringify(current) === JSON.stringify(submitted);
