import { z } from "zod";

import { DidSchema, HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const CanonicalIdSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Identifier must be lowercase",
);
const CanonicalHashSchema = HashHexSchema.refine(
  (value) => value === value.toLowerCase(),
  "Commitment must be lowercase",
);
const CanonicalUtcTimestampSchema = z.string().datetime({ offset: false }).refine(
  (value) => new Date(value).toISOString() === value,
  "Timestamp must be canonical UTC with milliseconds",
);

export const MAX_MUTATION_INTENT_LIFETIME_MS = 5 * 60 * 1000;

export const MutationIntentSchema = z.strictObject({
  version: z.literal("tr-mutation-intent-v1"),
  registryId: CanonicalIdSchema,
  actorDid: DidSchema.startsWith("did:midnight:").refine(
    (value) => !/[\s#]/u.test(value),
    "Actor must be a DID without whitespace or a fragment",
  ),
  actorKeyId: z.string().regex(/^did:midnight:[^\s#]+#[A-Za-z0-9:._-]+$/u),
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
  if (intent.action === "submit" && (intent.actorRole !== "applicant" || intent.target === "epoch")) {
    ctx.addIssue({ code: "custom", path: ["action"], message: "Only an applicant may submit a membership application" });
  }
  if (intent.action !== "submit" && intent.actorRole !== "maintainer") {
    ctx.addIssue({ code: "custom", path: ["actorRole"], message: "Governed actions require a maintainer" });
  }
  if ((intent.action === "publish-epoch") !== (intent.target === "epoch")) {
    ctx.addIssue({ code: "custom", path: ["target"], message: "Epoch target is reserved for epoch publication" });
  }
  const lifetime = Date.parse(intent.expiresAt) - Date.parse(intent.issuedAt);
  if (lifetime <= 0 || lifetime > MAX_MUTATION_INTENT_LIFETIME_MS) {
    ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "Intent lifetime must be positive and at most five minutes" });
  }
});

export type MutationIntent = z.infer<typeof MutationIntentSchema>;

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
