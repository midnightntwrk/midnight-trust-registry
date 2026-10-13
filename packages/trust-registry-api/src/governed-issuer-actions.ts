import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  decodeCanonicalJubjubSignatureHex,
  type TrustRegistryJubjubSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { z } from "zod";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ScalarSchema = z.string().regex(/^(0|[1-9][0-9]{0,78})$/u);

export const GovernedIssuerActionSchema = z.enum(["approve", "activate"]);

export const PreparedGovernedIssuerActionSchema = z.strictObject({
  registryId: Bytes32Schema,
  authorizationId: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  previousLifecycleEventHash: Bytes32Schema,
  evidenceHash: Bytes32Schema,
});

export const GovernedIssuerSignatureRequestSchema = z.strictObject({
  prepared: PreparedGovernedIssuerActionSchema,
  signers: z.array(z.strictObject({
    keyId: Bytes32Schema,
    publicKey: z.strictObject({ x: ScalarSchema, y: ScalarSchema }),
    signature: z.string().regex(/^0x[0-9a-f]+$/u),
  })).min(1).max(16),
});

export const GovernedIssuerActionReceiptSchema = z.strictObject({
  eventHash: Bytes32Schema,
});

export type GovernedIssuerAction = z.infer<typeof GovernedIssuerActionSchema>;
export type PreparedGovernedIssuerAction = z.infer<typeof PreparedGovernedIssuerActionSchema>;
export type GovernedIssuerSignatureRequest = z.infer<typeof GovernedIssuerSignatureRequestSchema>;
export type GovernedIssuerActionReceipt = z.infer<typeof GovernedIssuerActionReceiptSchema>;

export type GovernedIssuerActionContext = {
  registryId: Uint8Array;
  authorizationId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  previousLifecycleEventHash: Uint8Array;
  evidenceHash: Uint8Array;
};

export type GovernedIssuerSigner = {
  keyId: Uint8Array;
  publicKey: JubjubPoint;
  signature: TrustRegistryJubjubSignature;
};

export type GovernedIssuerActionPort = {
  prepare(authorizationId: string, action: GovernedIssuerAction): Promise<GovernedIssuerActionContext>;
  /** Recheck current policy, sequence, membership, quorum, and lifecycle in Compact before acceptance. */
  execute(
    authorizationId: string,
    action: GovernedIssuerAction,
    signers: readonly GovernedIssuerSigner[],
  ): Promise<GovernedIssuerActionReceipt>;
};

export class GovernedIssuerActionRejectedError extends Error {
  constructor(readonly reason: "invalid-signers" | "unknown-authorization") {
    super(`Governed issuer action rejected: ${reason}`);
    this.name = "GovernedIssuerActionRejectedError";
  }
}

const bytes32Hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Governed action context must contain bytes32 values");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const serializeGovernedIssuerAction = (
  context: GovernedIssuerActionContext,
): PreparedGovernedIssuerAction => PreparedGovernedIssuerActionSchema.parse({
  registryId: bytes32Hex(context.registryId),
  authorizationId: bytes32Hex(context.authorizationId),
  policyCommitment: bytes32Hex(context.policyCommitment),
  actionKind: bytes32Hex(context.actionKind),
  actionPayloadHash: bytes32Hex(context.actionPayloadHash),
  actionSequence: context.actionSequence.toString(),
  previousLifecycleEventHash: bytes32Hex(context.previousLifecycleEventHash),
  evidenceHash: bytes32Hex(context.evidenceHash),
});

export const sameGovernedIssuerAction = (
  current: PreparedGovernedIssuerAction,
  submitted: PreparedGovernedIssuerAction,
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

export const decodeGovernedIssuerSigners = (
  request: GovernedIssuerSignatureRequest,
): GovernedIssuerSigner[] => request.signers.map((signer) => ({
  keyId: Buffer.from(signer.keyId.slice(2), "hex"),
  publicKey: { x: BigInt(signer.publicKey.x), y: BigInt(signer.publicKey.y) },
  signature: decodeCanonicalJubjubSignatureHex(signer.signature),
}));
