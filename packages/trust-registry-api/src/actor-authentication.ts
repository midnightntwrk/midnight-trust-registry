import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";

import {
  resolveMidnightDIDMethodBinding,
  type ResolveMidnightDIDMethodBindingOptions,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { verifyJubjubPayload } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { decodeCanonicalJubjubSignatureHex, isPrimeOrderJubjubPoint } from "@midnight-ntwrk/trust-registry-contract";
import {
  ActorAuthenticationChallengeSchema,
  ActorAuthenticationContextSchema,
  MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS,
  MutationIntentSignatureSchema,
  actorAuthenticationDigestBytes,
  type ActorAuthenticationChallenge,
  type ActorAuthenticationContext,
  type ActorAuthenticationPurpose,
} from "@midnight-ntwrk/trust-registry-domain";

type MidnightResolver = ResolveMidnightDIDMethodBindingOptions["resolver"];

export interface ActorAuthenticationChallengeStore {
  /** Insert and consume must be atomic across every process serving this deployment. */
  insert(digest: string, actorHash: string, expiresAtMs: number, nowMs: number): Promise<boolean>;
  /** Compare expiry against the store's current time at the atomic consume, never an earlier caller timestamp. */
  consume(digest: string, nowMs: number): Promise<boolean>;
}

export class ActorAuthenticationResolverUnavailableError extends Error {
  constructor(cause: unknown) {
    super("Midnight DID resolver is unavailable", { cause });
    this.name = "ActorAuthenticationResolverUnavailableError";
  }
}

export class ActorAuthenticationCapacityError extends Error {
  constructor() {
    super("Actor authentication challenge capacity unavailable");
    this.name = "ActorAuthenticationCapacityError";
  }
}

export class InvalidActorAuthenticationIdentityError extends Error {
  constructor() {
    super("Actor DID authentication key is invalid");
    this.name = "InvalidActorAuthenticationIdentityError";
  }
}

function isDeterministicResolutionError(error: unknown): boolean {
  if (!(error instanceof Error) || !(
    error.name === "ResolverRequestError" || error.name === "InvalidDIDDocumentError"
  )) return false;
  const code = (error as Error & { resolutionCode?: unknown }).resolutionCode;
  return code === "invalidDid" || code === "methodNotSupported"
    || code === "invalidPublicKey" || code === "notAllowedLocalDuplicateKey";
}

/** Authentication proves DID-key control only; role and mutation authorization remain separate. */
export function createActorAuthenticationService(input: {
  context: ActorAuthenticationContext;
  store: ActorAuthenticationChallengeStore;
  resolver: MidnightResolver;
  clock: () => number;
}) {
  const context = ActorAuthenticationContextSchema.parse(input.context);
  return {
    origin: context.origin,
    async issue(actorDid: string, actorKeyId: string, purpose: ActorAuthenticationPurpose): Promise<ActorAuthenticationChallenge> {
      const nowMs = input.clock();
      if (!Number.isSafeInteger(nowMs)) throw new Error("Actor authentication clock unavailable");
      let did: ReturnType<typeof parseMidnightDIDString>;
      try {
        did = parseMidnightDIDString(actorDid);
      } catch {
        throw new InvalidActorAuthenticationIdentityError();
      }
      let resolved: Awaited<ReturnType<MidnightResolver["resolveResult"]>>;
      try {
        resolved = await input.resolver.resolveResult(did);
      } catch (error) {
        if (isDeterministicResolutionError(error)) throw new InvalidActorAuthenticationIdentityError();
        throw new ActorAuthenticationResolverUnavailableError(error);
      }
      try {
        const method = await resolveMidnightDIDMethodBinding({
          resolver: { resolveResult: async () => resolved },
          did,
          verificationMethodId: `#${actorKeyId.split("#")[1]}`,
          relationship: "authentication",
        });
        if (actorKeyId !== `${actorDid}#${actorKeyId.split("#")[1]}` || !isPrimeOrderJubjubPoint(method.publicKey)) {
          throw new InvalidActorAuthenticationIdentityError();
        }
      } catch {
        throw new InvalidActorAuthenticationIdentityError();
      }
      const challenge = ActorAuthenticationChallengeSchema.parse({
        version: "tr-actor-authentication-v1",
        ...context,
        purpose,
        actorDid,
        actorKeyId,
        nonce: `0x${randomBytes(32).toString("hex")}`,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS).toISOString(),
      });
      const digest = `0x${Buffer.from(actorAuthenticationDigestBytes(challenge)).toString("hex")}`;
      const actorHash = `0x${createHash("sha256").update(`tr-actor-auth-subject-v1:${challenge.actorDid}`).digest("hex")}`;
      if (!await input.store.insert(digest, actorHash, Date.parse(challenge.expiresAt), nowMs)) {
        throw new ActorAuthenticationCapacityError();
      }
      return challenge;
    },
    async verify(
      challengeInput: unknown,
      signatureInput: unknown,
      purpose: ActorAuthenticationPurpose,
    ): Promise<{ actorDid: string; actorKeyId: string } | null> {
      const parsedChallenge = ActorAuthenticationChallengeSchema.safeParse(challengeInput);
      const parsedSignature = MutationIntentSignatureSchema.safeParse(signatureInput);
      if (!parsedChallenge.success || !parsedSignature.success) return null;
      const challenge = parsedChallenge.data;
      const signature = parsedSignature.data;
      const nowMs = input.clock();
      if (!Number.isSafeInteger(nowMs)) throw new Error("Actor authentication clock unavailable");
      if (challenge.registryId !== context.registryId || challenge.genesisHash !== context.genesisHash
        || challenge.contractAddress !== context.contractAddress || challenge.origin !== context.origin
        || challenge.purpose !== purpose || signature.keyId !== challenge.actorKeyId
        || nowMs < Date.parse(challenge.issuedAt) || nowMs >= Date.parse(challenge.expiresAt)) return null;

      let did: ReturnType<typeof parseMidnightDIDString>;
      try {
        did = parseMidnightDIDString(challenge.actorDid);
      } catch {
        return null;
      }
      let resolved: Awaited<ReturnType<MidnightResolver["resolveResult"]>>;
      try {
        resolved = await input.resolver.resolveResult(did);
      } catch (error) {
        if (isDeterministicResolutionError(error)) return null;
        throw new ActorAuthenticationResolverUnavailableError(error);
      }
      let verified = false;
      try {
        const method = await resolveMidnightDIDMethodBinding({
          resolver: { resolveResult: async () => resolved },
          did,
          verificationMethodId: `#${challenge.actorKeyId.split("#")[1]}`,
          relationship: "authentication",
        });
        verified = isPrimeOrderJubjubPoint(method.publicKey) && verifyJubjubPayload(
          method.publicKey,
          actorAuthenticationDigestBytes(challenge),
          decodeCanonicalJubjubSignatureHex(signature.value),
        );
      } catch {
        return null;
      }
      if (!verified) return null;
      const consumeAtMs = input.clock();
      if (!Number.isSafeInteger(consumeAtMs)) throw new Error("Actor authentication clock unavailable");
      if (consumeAtMs < Date.parse(challenge.issuedAt) || consumeAtMs >= Date.parse(challenge.expiresAt)
        || !await input.store.consume(
          `0x${Buffer.from(actorAuthenticationDigestBytes(challenge)).toString("hex")}`, consumeAtMs,
        )
      ) return null;
      return { actorDid: challenge.actorDid, actorKeyId: challenge.actorKeyId };
    },
  };
}
