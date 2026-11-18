import { Buffer } from "node:buffer";
import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";

import {
  resolveMidnightDIDMethodBinding,
  type ResolveMidnightDIDMethodBindingOptions,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, resolveLongFormOffchainMidnightDID } from "@midnight-ntwrk/midnight-did";
import { verifyJubjubPayload } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { decodeCanonicalJubjubSignatureHex, isPrimeOrderJubjubPoint } from "@midnightntwrk/trust-registry-contract";
import {
  ActorAuthenticationChallengeSchema,
  ActorAuthenticationContextSchema,
  ActorAuthenticationSignatureSchema,
  MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS,
  actorAuthenticationDigestBytes,
  type ActorAuthenticationChallenge,
  type ActorAuthenticationContext,
  type ActorAuthenticationPurpose,
} from "@midnightntwrk/trust-registry-domain";

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
  resolver?: MidnightResolver;
  allowedModes?: "both" | "offchain-only" | "ledger-only";
  clock: () => number;
}) {
  const context = ActorAuthenticationContextSchema.parse(input.context);
  return {
    origin: context.origin,
    async issue(actorDid: string, actorKeyId: string, purpose: ActorAuthenticationPurpose): Promise<ActorAuthenticationChallenge> {
      const nowMs = input.clock();
      if (!Number.isSafeInteger(nowMs)) throw new Error("Actor authentication clock unavailable");
      const offchain = actorDid.startsWith("did:midnight:offchain:");
      if ((offchain && input.allowedModes === "ledger-only")
        || (!offchain && input.allowedModes === "offchain-only")) {
        throw new InvalidActorAuthenticationIdentityError();
      }
      if (offchain) {
        try {
          const resolved = resolveLongFormOffchainMidnightDID(actorDid);
          const method = resolved.didDocument.verificationMethod?.find((candidate) =>
            String(candidate.id) === actorKeyId && String(candidate.controller) === actorDid);
          if (resolved.did !== actorDid || resolved.didDocumentMetadata.deactivated === true
            || !resolved.didDocument.authentication?.some((entry) => String(entry) === actorKeyId)
            || method?.publicKeyJwk.kty !== "OKP" || method.publicKeyJwk.crv !== "Ed25519"
            || typeof method.publicKeyJwk.x !== "string") {
            throw new InvalidActorAuthenticationIdentityError();
          }
        } catch {
          throw new InvalidActorAuthenticationIdentityError();
        }
      } else {
        if (input.resolver === undefined) {
          throw new ActorAuthenticationResolverUnavailableError(new Error("Resolver not configured"));
        }
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
      }
      const challenge = ActorAuthenticationChallengeSchema.parse({
        version: offchain ? "tr-actor-authentication-offchain-v1" : "tr-actor-authentication-v1",
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
      const parsedSignature = ActorAuthenticationSignatureSchema.safeParse(signatureInput);
      if (!parsedChallenge.success || !parsedSignature.success) return null;
      const challenge = parsedChallenge.data;
      const signature = parsedSignature.data;
      if ((challenge.version === "tr-actor-authentication-offchain-v1" && input.allowedModes === "ledger-only")
        || (challenge.version === "tr-actor-authentication-v1" && input.allowedModes === "offchain-only")) return null;
      const nowMs = input.clock();
      if (!Number.isSafeInteger(nowMs)) throw new Error("Actor authentication clock unavailable");
      if (challenge.registryId !== context.registryId || challenge.genesisHash !== context.genesisHash
        || challenge.contractAddress !== context.contractAddress || challenge.origin !== context.origin
        || challenge.purpose !== purpose || signature.keyId !== challenge.actorKeyId
        || nowMs < Date.parse(challenge.issuedAt) || nowMs >= Date.parse(challenge.expiresAt)) return null;

      let verified = false;
      if (challenge.version === "tr-actor-authentication-offchain-v1") {
        if (signature.algorithm !== "ed25519") return null;
        try {
          const resolved = resolveLongFormOffchainMidnightDID(challenge.actorDid);
          if (resolved.did !== challenge.actorDid || resolved.didDocumentMetadata.deactivated === true) return null;
          const method = resolved.didDocument.verificationMethod?.find((candidate) =>
            String(candidate.id) === challenge.actorKeyId && String(candidate.controller) === challenge.actorDid);
          const authenticated = resolved.didDocument.authentication?.some((entry) =>
            String(entry) === challenge.actorKeyId) === true;
          if (method?.publicKeyJwk.kty !== "OKP" || method.publicKeyJwk.crv !== "Ed25519"
            || typeof method.publicKeyJwk.x !== "string" || !authenticated) return null;
          const key = createPublicKey({ key: {
            kty: "OKP", crv: "Ed25519", x: method.publicKeyJwk.x,
          }, format: "jwk" });
          verified = verifySignature(null, actorAuthenticationDigestBytes(challenge), key,
            Buffer.from(signature.value.slice(2), "hex"));
        } catch {
          return null;
        }
      } else {
        if (signature.algorithm !== "jubjub-schnorr") return null;
        if (input.resolver === undefined) throw new ActorAuthenticationResolverUnavailableError(new Error("Resolver not configured"));
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
