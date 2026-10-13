import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  decodeCanonicalJubjubSignatureHex,
  type TrustRegistryJubjubSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { z } from "zod";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ScalarSchema = z.string().regex(/^(0|[1-9][0-9]{0,78})$/u);

export const GovernedMembershipRoleSchema = z.enum(["issuer", "verifier", "auditor", "maintainer"]);
export const GovernedMembershipActionSchema = z.enum(["approve", "activate"]);

export const PreparedGovernedMembershipActionSchema = z.strictObject({
  registryId: Bytes32Schema,
  authorizationId: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  previousLifecycleEventHash: Bytes32Schema,
  evidenceHash: Bytes32Schema,
});

export const GovernedMembershipSignatureRequestSchema = z.strictObject({
  prepared: PreparedGovernedMembershipActionSchema,
  signers: z.array(z.strictObject({
    keyId: Bytes32Schema,
    publicKey: z.strictObject({ x: ScalarSchema, y: ScalarSchema }),
    signature: z.string().regex(/^0x[0-9a-f]+$/u),
  })).min(1).max(16),
});

export const GovernedMembershipActionReceiptSchema = z.strictObject({
  eventHash: Bytes32Schema,
});

export type GovernedMembershipRole = z.infer<typeof GovernedMembershipRoleSchema>;
export type GovernedMembershipAction = z.infer<typeof GovernedMembershipActionSchema>;
export type PreparedGovernedMembershipAction = z.infer<typeof PreparedGovernedMembershipActionSchema>;
export type GovernedMembershipSignatureRequest = z.infer<typeof GovernedMembershipSignatureRequestSchema>;
export type GovernedMembershipActionReceipt = z.infer<typeof GovernedMembershipActionReceiptSchema>;

export type GovernedMembershipActionContext = {
  registryId: Uint8Array;
  authorizationId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  previousLifecycleEventHash: Uint8Array;
  evidenceHash: Uint8Array;
};

export type GovernedMembershipSigner = {
  keyId: Uint8Array;
  publicKey: JubjubPoint;
  signature: TrustRegistryJubjubSignature;
};

export type GovernedMembershipActionPort = {
  prepare(role: GovernedMembershipRole, authorizationId: string, action: GovernedMembershipAction): Promise<GovernedMembershipActionContext>;
  /** Recheck current policy, sequence, membership, quorum, and lifecycle in Compact before acceptance. */
  execute(
    role: GovernedMembershipRole,
    authorizationId: string,
    action: GovernedMembershipAction,
    signers: readonly GovernedMembershipSigner[],
  ): Promise<GovernedMembershipActionReceipt>;
};

export class GovernedMembershipActionRejectedError extends Error {
  constructor(readonly reason: "invalid-signers" | "unknown-authorization") {
    super(`Governed membership action rejected: ${reason}`);
    this.name = "GovernedMembershipActionRejectedError";
  }
}

const bytes32Hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Governed action context must contain bytes32 values");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const serializeGovernedMembershipAction = (
  context: GovernedMembershipActionContext,
): PreparedGovernedMembershipAction => PreparedGovernedMembershipActionSchema.parse({
  registryId: bytes32Hex(context.registryId),
  authorizationId: bytes32Hex(context.authorizationId),
  policyCommitment: bytes32Hex(context.policyCommitment),
  actionKind: bytes32Hex(context.actionKind),
  actionPayloadHash: bytes32Hex(context.actionPayloadHash),
  actionSequence: context.actionSequence.toString(),
  previousLifecycleEventHash: bytes32Hex(context.previousLifecycleEventHash),
  evidenceHash: bytes32Hex(context.evidenceHash),
});

export const sameGovernedMembershipAction = (
  current: PreparedGovernedMembershipAction,
  submitted: PreparedGovernedMembershipAction,
): boolean => (
  current.registryId === submitted.registryId
  && current.authorizationId === submitted.authorizationId
  && current.policyCommitment === submitted.policyCommitment
  && current.actionKind === submitted.actionKind
  && current.actionPayloadHash === submitted.actionPayloadHash
  && current.actionSequence === submitted.actionSequence
  && current.previousLifecycleEventHash === submitted.previousLifecycleEventHash
  && current.evidenceHash === submitted.evidenceHash
);

export const decodeGovernedMembershipSigners = (
  request: GovernedMembershipSignatureRequest,
): GovernedMembershipSigner[] => request.signers.map((signer) => ({
  keyId: Buffer.from(signer.keyId.slice(2), "hex"),
  publicKey: { x: BigInt(signer.publicKey.x), y: BigInt(signer.publicKey.y) },
  signature: decodeCanonicalJubjubSignatureHex(signer.signature),
}));
