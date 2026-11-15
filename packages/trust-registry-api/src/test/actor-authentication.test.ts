import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { createLongFormOffchainMidnightDIDString, CurveType, KeyType } from "@midnight-ntwrk/midnight-did-domain";
import { resolveLongFormOffchainMidnightDID } from "@midnight-ntwrk/midnight-did";
import {
  ActorAuthenticationChallengeSchema,
  actorAuthenticationDigestBytes,
  type ActorAuthenticationChallenge,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import {
  ActorAuthenticationResolverUnavailableError,
  createActorAuthenticationService,
  type ActorAuthenticationChallengeStore,
} from "../actor-authentication.js";
import { FileActorAuthenticationChallengeStore } from "../file-actor-authentication.js";

const seed = new Uint8Array(32).fill(67);
const did = createMidnightDid("actor-authentication");
const keyId = `${did}#auth-1`;
const context = {
  registryId: "tr:registry:local",
  genesisHash: `0x${"11".repeat(32)}`,
  contractAddress: `0x${"22".repeat(32)}`,
  origin: "http://127.0.0.1:4400",
};
const START = Date.parse("2026-11-14T00:00:00.000Z");

function memoryStore(): ActorAuthenticationChallengeStore {
  const entries = new Map<string, number>();
  return {
    async insert(digest, _actorHash, expiresAtMs, nowMs) {
      for (const [key, expiry] of entries) if (expiry <= nowMs) entries.delete(key);
      if (entries.has(digest)) return false;
      entries.set(digest, expiresAtMs);
      return true;
    },
    async consume(digest, nowMs) {
      const expiry = entries.get(digest);
      if (expiry === undefined || expiry <= nowMs) return false;
      entries.delete(digest);
      return true;
    },
  };
}

function signatureFor(challenge: ActorAuthenticationChallenge, signingSeed = seed) {
  return {
    keyId: challenge.actorKeyId,
    algorithm: "jubjub-schnorr" as const,
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      signingSeed, actorAuthenticationDigestBytes(challenge),
    ))).toString("hex")}`,
  };
}

const resolver = createMidnightDidResolver([
  createMidnightDidLedgerFixture(did, {
    verificationMethodId: "auth-1",
    schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
  }),
]);

describe("actor DID authentication challenge", () => {
  it("verifies once across file-store restart without reviving the signed challenge", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tr-actor-auth-service-"));
    try {
      const path = join(directory, "challenges.json");
      const first = createActorAuthenticationService({
        context, store: new FileActorAuthenticationChallengeStore(path, () => START), resolver, clock: () => START,
      });
      const challenge = await first.issue(did, keyId, "applicant-session");
      const signature = signatureFor(challenge);
      const restarted = createActorAuthenticationService({
        context, store: new FileActorAuthenticationChallengeStore(path, () => START), resolver, clock: () => START,
      });
      expect(await restarted.verify(challenge, signature, "applicant-session"))
        .toEqual({ actorDid: did, actorKeyId: keyId });
      expect(await first.verify(challenge, signature, "applicant-session")).toBeNull();
      expect(await restarted.verify(challenge, signature, "applicant-session")).toBeNull();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("authenticates one exact transcript once without granting a registry role", async () => {
    const store = memoryStore();
    const suppliedContext = { ...context };
    const service = createActorAuthenticationService({ context: suppliedContext, store, resolver, clock: () => START });
    suppliedContext.genesisHash = `0x${"44".repeat(32)}`;
    const challenge = await service.issue(did, keyId, "applicant-session");
    const signature = signatureFor(challenge);
    expect(challenge).toMatchObject({ ...context, actorDid: did, actorKeyId: keyId });
    expect(await service.verify(challenge, signature, "applicant-session")).toEqual({ actorDid: did, actorKeyId: keyId });
    expect(await service.verify(challenge, signature, "applicant-session")).toBeNull();
  });

  it("rejects changed context, purpose, subject, signature and extra fields without consuming", async () => {
    const store = memoryStore();
    const service = createActorAuthenticationService({ context, store, resolver, clock: () => START });
    const challenge = await service.issue(did, keyId, "applicant-session");
    const signature = signatureFor(challenge);
    const otherDeployment = createActorAuthenticationService({
      context: { ...context, genesisHash: `0x${"33".repeat(32)}` }, store, resolver, clock: () => START,
    });
    const otherOrigin = createActorAuthenticationService({
      context: { ...context, origin: "http://localhost:4400" }, store, resolver, clock: () => START,
    });
    const otherContract = createActorAuthenticationService({
      context: { ...context, contractAddress: `0x${"55".repeat(32)}` }, store, resolver, clock: () => START,
    });
    expect(await otherDeployment.verify(challenge, signature, "applicant-session")).toBeNull();
    expect(await otherOrigin.verify(challenge, signature, "applicant-session")).toBeNull();
    expect(await otherContract.verify(challenge, signature, "applicant-session")).toBeNull();
    expect(await service.verify(challenge, signature, "maintainer-session")).toBeNull();
    expect(await service.verify({ ...challenge, purpose: "maintainer-session" }, signature, "maintainer-session")).toBeNull();
    expect(await service.verify({ ...challenge, actorDid: createMidnightDid("other") }, signature, "applicant-session")).toBeNull();
    expect(await service.verify({ ...challenge, extra: true }, signature, "applicant-session")).toBeNull();
    expect(await service.verify(challenge, signatureFor(challenge, new Uint8Array(32).fill(68)), "applicant-session"))
      .toBeNull();
    expect(await service.verify(challenge, { ...signature, keyId: `${did}#other` }, "applicant-session"))
      .toBeNull();
    expect(await service.verify(challenge, signature, "applicant-session")).toEqual({ actorDid: did, actorKeyId: keyId });
  });

  it("rejects noncanonical or expired challenges and keys without an authentication relationship", async () => {
    let nowMs = START;
    const store = memoryStore();
    const service = createActorAuthenticationService({ context, store, resolver, clock: () => nowMs });
    await expect(service.issue(did, `${createMidnightDid("other")}#auth-1`, "applicant-session")).rejects.toThrow();
    await expect(service.issue(did, keyId, "invalid" as "applicant-session")).rejects.toThrow();
    const challenge = await service.issue(did, keyId, "applicant-session");
    expect(ActorAuthenticationChallengeSchema.safeParse({ ...challenge, origin: "http://example.com" }).success).toBe(false);
    expect(ActorAuthenticationChallengeSchema.safeParse({ ...challenge, genesisHash: `0x${"00".repeat(32)}` }).success)
      .toBe(false);
    expect(ActorAuthenticationChallengeSchema.safeParse({ ...challenge, expiresAt: challenge.issuedAt }).success).toBe(false);
    const assertionOnly = createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, {
        schnorrJubjubAuthenticationMethods: [],
        schnorrJubjubAssertionMethods: [{ id: "auth-1", publicKey: deriveJubjubPublicKeyFromSeed(seed) }],
      }),
    ]);
    const wrongRelationship = createActorAuthenticationService({ context, store, resolver: assertionOnly, clock: () => nowMs });
    expect(await wrongRelationship.verify(challenge, signatureFor(challenge), "applicant-session")).toBeNull();
    nowMs += 120_000;
    expect(await service.verify(challenge, signatureFor(challenge), "applicant-session")).toBeNull();
  });

  it("keeps a challenge available across resolver outage and fails closed on store failure", async () => {
    const store = memoryStore();
    const service = createActorAuthenticationService({ context, store, resolver, clock: () => START });
    const challenge = await service.issue(did, keyId, "applicant-session");
    const outage = new Error("RPC unavailable");
    const unavailable = createActorAuthenticationService({
      context, store, resolver: { resolveResult: async () => { throw outage; } }, clock: () => START,
    });
    await expect(unavailable.verify(challenge, signatureFor(challenge), "applicant-session"))
      .rejects.toMatchObject({ name: ActorAuthenticationResolverUnavailableError.name, cause: outage });
    const noConsume = createActorAuthenticationService({
      context, store: { ...store, consume: async () => false }, resolver, clock: () => START,
    });
    expect(await noConsume.verify(challenge, signatureFor(challenge), "applicant-session")).toBeNull();
    expect(await service.verify(challenge, signatureFor(challenge), "applicant-session"))
      .toEqual({ actorDid: did, actorKeyId: keyId });
  });

  it("rejects a DID deactivated after challenge issuance without consuming the challenge", async () => {
    const store = memoryStore();
    const service = createActorAuthenticationService({ context, store, resolver, clock: () => START });
    const challenge = await service.issue(did, keyId, "applicant-session");
    const fixture = createMidnightDidLedgerFixture(did, {
      verificationMethodId: "auth-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
    });
    const deactivatedResolver = createMidnightDidResolver([{
      ...fixture,
      ledgerState: { ...fixture.ledgerState, active: false, deactivated: true },
    }]);
    const deactivated = createActorAuthenticationService({
      context, store, resolver: deactivatedResolver, clock: () => START,
    });
    expect(await deactivated.verify(challenge, signatureFor(challenge), "applicant-session")).toBeNull();
    expect(await service.verify(challenge, signatureFor(challenge), "applicant-session"))
      .toEqual({ actorDid: did, actorKeyId: keyId });
  });

  it("authenticates an off-chain long-form Ed25519 DID once and rejects changed state or relationship", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const state = {
      version: 1,
      alsoKnownAs: [],
      verificationMethod: [{
        id: "#auth-1",
        publicKeyJwk: { kty: KeyType.OKP, crv: CurveType.Ed25519, x: publicJwk.x! },
        relationships: { authentication: true, assertionMethod: false, keyAgreement: false,
          capabilityInvocation: false, capabilityDelegation: false },
      }],
      service: [],
    };
    const actorDid = createLongFormOffchainMidnightDIDString(state);
    expect(resolveLongFormOffchainMidnightDID(actorDid).did).toBe(actorDid);
    const actorKeyId = `${actorDid}#auth-1`;
    const store = memoryStore();
    const service = createActorAuthenticationService({ context, store, clock: () => START });
    const challenge = await service.issue(actorDid, actorKeyId, "applicant-session");
    expect(challenge).toMatchObject({ version: "tr-actor-authentication-offchain-v1",
      actorDid });
    const signature = {
      keyId: actorKeyId, algorithm: "ed25519",
      value: `0x${signEd25519(null, actorAuthenticationDigestBytes(challenge), privateKey).toString("hex")}`,
    };
    const stateStart = actorDid.lastIndexOf(":") + 1;
    const changedDid = `${actorDid.slice(0, stateStart)}${actorDid[stateStart] === "A" ? "B" : "A"}${actorDid.slice(stateStart + 1)}`;
    await expect(service.issue(changedDid, `${changedDid}#auth-1`, "applicant-session"))
      .rejects.toMatchObject({ name: "InvalidActorAuthenticationIdentityError" });
    expect(await service.verify(challenge, { ...signature, value: `0x${"00".repeat(64)}` },
      "applicant-session")).toBeNull();
    expect(await service.verify(challenge, signature, "applicant-session"))
      .toEqual({ actorDid, actorKeyId });
    expect(await service.verify(challenge, signature, "applicant-session")).toBeNull();

    const assertionDid = createLongFormOffchainMidnightDIDString({
      ...state,
      verificationMethod: [{ ...state.verificationMethod[0]!,
        relationships: { ...state.verificationMethod[0]!.relationships, authentication: false,
          assertionMethod: true } }],
    });
    const assertionChallenge = await service.issue(assertionDid, `${assertionDid}#auth-1`,
      "applicant-session");
    const assertionSignature = {
      keyId: `${assertionDid}#auth-1`, algorithm: "ed25519",
      value: `0x${signEd25519(null, actorAuthenticationDigestBytes(assertionChallenge), privateKey).toString("hex")}`,
    };
    expect(await service.verify(assertionChallenge, assertionSignature, "applicant-session")).toBeNull();
  });

  it("accepts a resolved path authentication method but not another DID's method", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const actorDid = createLongFormOffchainMidnightDIDString({
      version: 1,
      alsoKnownAs: [],
      verificationMethod: [{
        id: "./keys#auth",
        publicKeyJwk: { kty: KeyType.OKP, crv: CurveType.Ed25519, x: publicJwk.x! },
        relationships: { authentication: true, assertionMethod: false, keyAgreement: false,
          capabilityInvocation: false, capabilityDelegation: false },
      }],
      service: [],
    });
    const actorKeyId = `${actorDid}/keys#auth`;
    expect(resolveLongFormOffchainMidnightDID(actorDid).didDocument.authentication).toContain(actorKeyId);
    const service = createActorAuthenticationService({ context, store: memoryStore(), clock: () => START });
    await expect(service.issue(actorDid, `${did}/keys#auth`, "applicant-session")).rejects.toThrow();
    const challenge = await service.issue(actorDid, actorKeyId, "applicant-session");
    const signature = {
      keyId: actorKeyId,
      algorithm: "ed25519",
      value: `0x${signEd25519(null, actorAuthenticationDigestBytes(challenge), privateKey).toString("hex")}`,
    };
    expect(await service.verify(challenge, signature, "applicant-session"))
      .toEqual({ actorDid, actorKeyId });
  });

  it("rejects a challenge that expires during DID resolution before store consumption", async () => {
    let nowMs = START;
    const store = {
      ...memoryStore(),
      consume: async () => { throw new Error("Expired challenge must not reach the store"); },
    };
    const delayedResolver = {
      resolveResult: async (parsedDid: Parameters<typeof resolver.resolveResult>[0]) => {
        nowMs += 120_000;
        return resolver.resolveResult(parsedDid);
      },
    };
    const service = createActorAuthenticationService({ context, store, resolver: delayedResolver, clock: () => nowMs });
    const challenge = await service.issue(did, keyId, "applicant-session");
    expect(await service.verify(challenge, signatureFor(challenge), "applicant-session")).toBeNull();
  });
});
