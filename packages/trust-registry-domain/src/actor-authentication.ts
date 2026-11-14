import { hexToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";

import { HashHexSchema, ScopedIdentifierSchema, sha256Hex } from "./ids.js";

const CanonicalHashSchema = HashHexSchema.refine((value) => value === value.toLowerCase());
const DeploymentHashSchema = CanonicalHashSchema.refine((value) => !/^0x0{64}$/u.test(value));
const CanonicalDidSchema = z.string().regex(
  /^did:midnight:(?:undeployed|devnet|testnet|mainnet|preview|preprod):[0-9a-f]{64}$/u,
);
const CanonicalKeySchema = z.string().regex(
  /^did:midnight:(?:undeployed|devnet|testnet|mainnet|preview|preprod):[0-9a-f]{64}#[A-Za-z0-9:._-]+$/u,
);
const CanonicalTimestampSchema = z.string().datetime({ offset: false }).refine(
  (value) => new Date(value).toISOString() === value,
);
const OriginSchema = z.url().refine((value) => {
  const url = new URL(value);
  return url.origin === value && (url.protocol === "https:"
    || (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)));
});

export const MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS = 2 * 60 * 1000;

export const ActorAuthenticationContextSchema = z.strictObject({
  registryId: ScopedIdentifierSchema.refine((value) => value === value.toLowerCase()),
  genesisHash: DeploymentHashSchema,
  contractAddress: DeploymentHashSchema,
  origin: OriginSchema,
});

export const ActorAuthenticationChallengeSchema = ActorAuthenticationContextSchema.extend({
  version: z.literal("tr-actor-authentication-v1"),
  purpose: z.enum(["applicant-session", "maintainer-session"]),
  actorDid: CanonicalDidSchema,
  actorKeyId: CanonicalKeySchema,
  nonce: CanonicalHashSchema,
  issuedAt: CanonicalTimestampSchema,
  expiresAt: CanonicalTimestampSchema,
}).superRefine((challenge, context) => {
  if (!challenge.actorKeyId.startsWith(`${challenge.actorDid}#`)) {
    context.addIssue({ code: "custom", path: ["actorKeyId"], message: "Key must belong to actor DID" });
  }
  const lifetime = Date.parse(challenge.expiresAt) - Date.parse(challenge.issuedAt);
  if (lifetime <= 0 || lifetime > MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "Challenge lifetime is invalid" });
  }
});

export type ActorAuthenticationChallenge = z.infer<typeof ActorAuthenticationChallengeSchema>;
export type ActorAuthenticationContext = z.infer<typeof ActorAuthenticationContextSchema>;
export type ActorAuthenticationPurpose = ActorAuthenticationChallenge["purpose"];

export function actorAuthenticationDigestBytes(input: ActorAuthenticationChallenge): Uint8Array {
  const challenge = ActorAuthenticationChallengeSchema.parse(input);
  const digest = sha256Hex(JSON.stringify([
    "tr:actor:authentication:v1",
    challenge.version,
    challenge.registryId,
    challenge.genesisHash,
    challenge.contractAddress,
    challenge.origin,
    challenge.purpose,
    challenge.actorDid,
    challenge.actorKeyId,
    challenge.nonce,
    challenge.issuedAt,
    challenge.expiresAt,
  ]));
  return hexToBytes(digest.slice(2));
}
