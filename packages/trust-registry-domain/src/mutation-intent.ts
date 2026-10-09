import { z } from "zod";
import { hexToBytes } from "@noble/hashes/utils.js";

import { HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const CanonicalIdSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Identifier must be lowercase",
);
const CanonicalHashSchema = HashHexSchema.refine(
  (value) => value === value.toLowerCase(),
  "Commitment must be lowercase",
);
const CanonicalUtcTimestampSchema = z.string().datetime({ offset: false }).refine(
  (value) => {
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
  },
  "Timestamp must be canonical UTC with milliseconds",
);
const MidnightDidPattern = /^did:midnight:(?:undeployed|devnet|testnet|mainnet|preview|preprod):[0-9a-f]{64}$/u;
const MidnightKeyPattern = /^did:midnight:(?:undeployed|devnet|testnet|mainnet|preview|preprod):[0-9a-f]{64}#[A-Za-z0-9:._-]+$/u;

export const MAX_MUTATION_INTENT_LIFETIME_MS = 5 * 60 * 1000;

export const MutationIntentSchema = z.strictObject({
  version: z.literal("tr-mutation-intent-v1"),
  registryId: CanonicalIdSchema,
  actorDid: z.string().regex(MidnightDidPattern, "Actor DID must be a canonical four-part Midnight DID"),
  actorKeyId: z.string().regex(MidnightKeyPattern, "Actor key must use a canonical Midnight DID fragment"),
  actorRole: z.enum(["applicant", "maintainer"]),
  action: z.enum(["submit", "approve", "activate", "suspend", "revoke", "archive", "publish-epoch"]),
  target: z.enum(["issuer", "verifier", "auditor", "recognition", "maintainer", "epoch"]),
  targetId: CanonicalIdSchema,
  scopeCommitment: CanonicalHashSchema,
  payloadCommitment: CanonicalHashSchema,
  nonce: CanonicalHashSchema,
  expectedWorkspaceCommitment: CanonicalHashSchema,
  expectedEpochId: CanonicalIdSchema.nullable(),
  issuedAt: CanonicalUtcTimestampSchema,
  expiresAt: CanonicalUtcTimestampSchema,
}).superRefine((intent, ctx) => {
  if (!intent.actorKeyId.startsWith(`${intent.actorDid}#`)) {
    ctx.addIssue({ code: "custom", path: ["actorKeyId"], message: "Verification method must belong to the actor DID" });
  }
  if (intent.action === "submit" && intent.target === "recognition" && intent.actorRole !== "maintainer") {
    ctx.addIssue({ code: "custom", path: ["actorRole"], message: "Recognition proposals require a maintainer" });
  }
  if (intent.action === "submit" && ["issuer", "verifier", "auditor"].includes(intent.target) && intent.actorRole !== "applicant") {
    ctx.addIssue({ code: "custom", path: ["actorRole"], message: "Membership applications require an applicant" });
  }
  if (intent.action !== "submit" && intent.actorRole !== "maintainer") {
    ctx.addIssue({ code: "custom", path: ["actorRole"], message: "Governed actions require a maintainer" });
  }
  if ((intent.action === "publish-epoch") !== (intent.target === "epoch")) {
    ctx.addIssue({ code: "custom", path: ["target"], message: "Epoch target is reserved for epoch publication" });
  }
  if (intent.action === "publish-epoch" && intent.targetId !== intent.expectedEpochId) {
    ctx.addIssue({ code: "custom", path: ["targetId"], message: "Epoch publication must target the expected predecessor epoch" });
  }
  const lifetime = Date.parse(intent.expiresAt) - Date.parse(intent.issuedAt);
  if (lifetime <= 0 || lifetime > MAX_MUTATION_INTENT_LIFETIME_MS) {
    ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "Intent lifetime must be positive and at most five minutes" });
  }
});

export type MutationIntent = z.infer<typeof MutationIntentSchema>;

export const MutationIntentSignatureSchema = z.strictObject({
  keyId: z.string().regex(MidnightKeyPattern),
  algorithm: z.literal("jubjub-schnorr"),
  value: z.string().regex(/^0x[0-9a-f]{192}$/u),
});

export type MutationIntentSignature = z.infer<typeof MutationIntentSignatureSchema>;

export function computeMutationIntentDigest(input: MutationIntent): string {
  const intent = MutationIntentSchema.parse(input);
  return sha256Hex(JSON.stringify([
    "tr:mutation:intent:v1",
    intent.registryId,
    intent.actorDid,
    intent.actorKeyId,
    intent.actorRole,
    intent.action,
    intent.target,
    intent.targetId,
    intent.scopeCommitment,
    intent.payloadCommitment,
    intent.nonce,
    intent.expectedWorkspaceCommitment,
    intent.expectedEpochId,
    intent.issuedAt,
    intent.expiresAt,
  ]));
}

export function mutationIntentDigestBytes(input: MutationIntent): Uint8Array {
  return hexToBytes(computeMutationIntentDigest(input).slice(2));
}
