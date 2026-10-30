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

export const GovernedMaintainerRecoveryPrepareRequestSchema = GovernedThresholdPrepareRequestSchema.extend({
  maintainerId: Bytes32Schema,
  evidenceHash: Bytes32Schema,
});

export const PreparedGovernedPolicyActionSchema = z.strictObject({
  registryId: Bytes32Schema,
  networkIdCommitment: Bytes32Schema,
  contractAddress: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  nextPolicyCommitment: Bytes32Schema.optional(),
  nextPolicyVersion: ScalarSchema.optional(),
  authorizationId: Bytes32Schema.optional(),
  keyIdCommitment: Bytes32Schema.optional(),
  newAuthorizationId: Bytes32Schema.optional(),
  newKeyIdCommitment: Bytes32Schema.optional(),
  newPublicKey: z.strictObject({ x: ScalarSchema, y: ScalarSchema }).optional(),
  reasonHash: Bytes32Schema.optional(),
  policyVersion: ScalarSchema.optional(),
  maintainerId: Bytes32Schema.optional(),
  previousLifecycleEventHash: Bytes32Schema.optional(),
  evidenceHash: Bytes32Schema.optional(),
});

export const GovernedThresholdSubmitRequestSchema = GovernedThresholdPrepareRequestSchema.extend({
  prepared: PreparedGovernedPolicyActionSchema,
  signers: GovernedMembershipSignersSchema,
});
export const GovernedMaintainerRecoverySubmitRequestSchema = GovernedMaintainerRecoveryPrepareRequestSchema.extend({
  prepared: PreparedGovernedPolicyActionSchema,
  signers: GovernedMembershipSignersSchema,
});

export const GovernedEvidenceVerifierPrepareRequestSchema = z.strictObject({});
export const GovernedEvidenceVerifierSubmitRequestSchema = z.strictObject({
  prepared: PreparedGovernedPolicyActionSchema,
  signers: GovernedMembershipSignersSchema,
});

export const GovernedEvidenceVerifierStatusPrepareRequestSchema = z.strictObject({
  authorizationId: Bytes32Schema,
  reasonHash: Bytes32Schema,
});
export const GovernedEvidenceVerifierRotationPrepareRequestSchema = GovernedEvidenceVerifierStatusPrepareRequestSchema
  .extend({
    newAuthorizationId: Bytes32Schema,
    newKeyIdCommitment: Bytes32Schema,
    newPublicKey: z.strictObject({ x: ScalarSchema, y: ScalarSchema }),
  });
export const PreparedGovernedEvidenceVerifierStatusSchema = PreparedGovernedPolicyActionSchema.extend({
  authorizationId: Bytes32Schema,
  previousLifecycleEventHash: Bytes32Schema,
  reasonHash: Bytes32Schema,
});
export const PreparedGovernedEvidenceVerifierRotationSchema = PreparedGovernedEvidenceVerifierStatusSchema.extend({
  newAuthorizationId: Bytes32Schema,
  newKeyIdCommitment: Bytes32Schema,
  newPublicKey: z.strictObject({ x: ScalarSchema, y: ScalarSchema }),
});
export const GovernedEvidenceVerifierStatusSubmitRequestSchema = GovernedEvidenceVerifierStatusPrepareRequestSchema
  .extend({ prepared: PreparedGovernedEvidenceVerifierStatusSchema, signers: GovernedMembershipSignersSchema });
export const GovernedEvidenceVerifierRotationSubmitRequestSchema = GovernedEvidenceVerifierRotationPrepareRequestSchema
  .extend({ prepared: PreparedGovernedEvidenceVerifierRotationSchema, signers: GovernedMembershipSignersSchema });

export const GovernedPolicyActionReceiptSchema = z.strictObject({ eventHash: Bytes32Schema });

export type GovernedThresholds = z.infer<typeof GovernedThresholdsSchema>;
export type PreparedGovernedPolicyAction = z.infer<typeof PreparedGovernedPolicyActionSchema>;
export type GovernedThresholdSubmitRequest = z.infer<typeof GovernedThresholdSubmitRequestSchema>;
export type GovernedEvidenceVerifierSubmitRequest = z.infer<typeof GovernedEvidenceVerifierSubmitRequestSchema>;
export type GovernedEvidenceVerifierTransitionInput =
  | ({ action: "suspend" | "revoke" } & z.infer<typeof GovernedEvidenceVerifierStatusPrepareRequestSchema>)
  | ({ action: "rotate" } & z.infer<typeof GovernedEvidenceVerifierRotationPrepareRequestSchema>);
export type GovernedPolicyActionReceipt = z.infer<typeof GovernedPolicyActionReceiptSchema>;

export type GovernedPolicyActionContext = {
  registryId: Uint8Array;
  networkIdCommitment: Uint8Array;
  contractAddress: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  nextPolicyCommitment?: Uint8Array;
  nextPolicyVersion?: bigint;
  authorizationId?: Uint8Array;
  keyIdCommitment?: Uint8Array;
  newAuthorizationId?: Uint8Array;
  newKeyIdCommitment?: Uint8Array;
  newPublicKey?: { x: bigint; y: bigint };
  reasonHash?: Uint8Array;
  policyVersion?: bigint;
  maintainerId?: Uint8Array;
  previousLifecycleEventHash?: Uint8Array;
  evidenceHash?: Uint8Array;
};

export type GovernedPolicyActionPort = {
  prepareThresholds(thresholds: GovernedThresholds): Promise<GovernedPolicyActionContext>;
  executeThresholds(
    thresholds: GovernedThresholds,
    signers: readonly GovernedMembershipSigner[],
  ): Promise<GovernedPolicyActionReceipt>;
  prepareEvidenceVerifier(): Promise<GovernedPolicyActionContext>;
  executeEvidenceVerifier(signers: readonly GovernedMembershipSigner[]): Promise<GovernedPolicyActionReceipt>;
  /** Implementations must authenticate replacement DID-key ownership and recheck the ledger at execution. */
  prepareEvidenceVerifierTransition?(
    input: GovernedEvidenceVerifierTransitionInput,
  ): Promise<GovernedPolicyActionContext>;
  executeEvidenceVerifierTransition?(
    input: GovernedEvidenceVerifierTransitionInput,
    signers: readonly GovernedMembershipSigner[],
  ): Promise<GovernedPolicyActionReceipt>;
  prepareMaintainerRecovery?(
    maintainerId: string,
    evidenceHash: string,
    thresholds: GovernedThresholds,
  ): Promise<GovernedPolicyActionContext>;
  executeMaintainerRecovery?(
    maintainerId: string,
    evidenceHash: string,
    thresholds: GovernedThresholds,
    signers: readonly GovernedMembershipSigner[],
  ): Promise<GovernedPolicyActionReceipt>;
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
  networkIdCommitment: bytes32Hex(context.networkIdCommitment),
  contractAddress: bytes32Hex(context.contractAddress),
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
  ...(context.newAuthorizationId === undefined ? {} : {
    newAuthorizationId: bytes32Hex(context.newAuthorizationId),
  }),
  ...(context.newKeyIdCommitment === undefined ? {} : {
    newKeyIdCommitment: bytes32Hex(context.newKeyIdCommitment),
  }),
  ...(context.newPublicKey === undefined ? {} : {
    newPublicKey: {
      x: context.newPublicKey.x.toString(), y: context.newPublicKey.y.toString(),
    },
  }),
  ...(context.reasonHash === undefined ? {} : {
    reasonHash: bytes32Hex(context.reasonHash),
  }),
  ...(context.policyVersion === undefined ? {} : {
    policyVersion: context.policyVersion.toString(),
  }),
  ...(context.maintainerId === undefined ? {} : {
    maintainerId: bytes32Hex(context.maintainerId),
  }),
  ...(context.previousLifecycleEventHash === undefined ? {} : {
    previousLifecycleEventHash: bytes32Hex(context.previousLifecycleEventHash),
  }),
  ...(context.evidenceHash === undefined ? {} : {
    evidenceHash: bytes32Hex(context.evidenceHash),
  }),
});

export const sameGovernedPolicyAction = (
  current: PreparedGovernedPolicyAction,
  submitted: PreparedGovernedPolicyAction,
): boolean => JSON.stringify(current) === JSON.stringify(submitted);
