import { Buffer } from "node:buffer";

import { createOperatorWorkspace, MAX_CONSUMED_MUTATION_NONCES } from "@midnight-ntwrk/trust-registry-cli";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  computeAuthorizationScopeCommitment,
  computeMutationPayloadCommitment,
  mutationIntentDigestBytes,
  sha256Hex,
  type MutationIntent,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  createIssuerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import { MutationIntentActorRejectedError, MutationNonceAlreadyUsedError, MutationNonceCapacityExceededError, transitionSignedMutationState } from "../signed-mutation-state.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const workspace = createOperatorWorkspace({ label: "signed-transition" });
const fixture = createIssuerScenarioFixture("example");
const actorDid = fixture.subjectDid;
const seed = new Uint8Array(32).fill(47);
const operation = { operation: "submit" as const, target: "issuer" as const, label: "example" };
const now = new Date("2026-10-10T00:01:00.000Z");
const intent: MutationIntent = {
  version: "tr-mutation-intent-v1",
  registryId: workspace.snapshot.registry.registryId,
  actorDid,
  actorKeyId: `${actorDid}#assertion-1`,
  actorRole: "applicant",
  action: "submit",
  target: "issuer",
  targetId: "auth:issuer:example:v1",
  scopeCommitment: computeAuthorizationScopeCommitment(fixture.authorizationScope),
  payloadCommitment: computeMutationPayloadCommitment({ target: "issuer", label: "example" }),
  nonce: `0x${"33".repeat(32)}`,
  expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
  expectedEpochId: workspace.snapshot.currentEpoch.epochId,
  issuedAt: "2026-10-10T00:00:00.000Z",
  expiresAt: "2026-10-10T00:05:00.000Z",
};
const signatureFor = (value: MutationIntent) => ({
  keyId: value.actorKeyId,
  algorithm: "jubjub-schnorr" as const,
  value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
    seed, mutationIntentDigestBytes(value),
  ))).toString("hex")}`,
});
const resolver = createMidnightDidResolver([
  createMidnightDidLedgerFixture(actorDid, {
    verificationMethodId: "assertion-1",
    schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
  }),
]);

describe("pure signed mutation state transition", () => {
  it("applies a valid operation and consumes its nonce only in the returned state", async () => {
    const initial = { workspace, consumedNonces: {} } as const;
    const next = await transitionSignedMutationState(initial, intent, signatureFor(intent), operation, now, resolver);
    expect(next.workspace.operations).toHaveLength(1);
    const nonceKey = sha256Hex(JSON.stringify(["tr:mutation:nonce:v2", intent.registryId, actorDid, intent.nonce]));
    expect(next.consumedNonces).toEqual({ [nonceKey]: intent.expiresAt });
    expect(initial.workspace.operations).toHaveLength(0);
    expect(Object.keys(initial.consumedNonces)).toHaveLength(0);

    const newRevision = { ...intent, expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(next.workspace) };
    await expect(transitionSignedMutationState(next, newRevision, signatureFor(newRevision), operation, now, resolver))
      .rejects.toBeInstanceOf(MutationNonceAlreadyUsedError);
    expect(Object.keys(next.consumedNonces)).toHaveLength(1);
  });

  it("does not consume a nonce when signature or operation binding fails", async () => {
    const initial = { workspace, consumedNonces: {} } as const;
    await expect(transitionSignedMutationState(
      initial, intent, { ...signatureFor(intent), value: `0x${"00".repeat(96)}` }, operation, now, resolver,
    )).rejects.toBeInstanceOf(MutationIntentActorRejectedError);
    await expect(transitionSignedMutationState(
      initial, intent, signatureFor(intent), { ...operation, label: "other" }, now, resolver,
    )).rejects.toBeInstanceOf(MutationIntentActorRejectedError);
    expect(Object.keys(initial.consumedNonces)).toHaveLength(0);
    expect(initial.workspace.operations).toHaveLength(0);
  });

  it("prunes expired nonce entries while retaining every live identity", async () => {
    const expiredKey = sha256Hex("expired");
    const liveKey = sha256Hex("live");
    const initial = {
      workspace,
      consumedNonces: {
        [expiredKey]: "2026-10-10T00:01:00.000Z",
        [liveKey]: "2026-10-10T00:02:00.000Z",
      },
    };
    const next = await transitionSignedMutationState(initial, intent, signatureFor(intent), operation, now, resolver);
    expect(next.consumedNonces[expiredKey]).toBeUndefined();
    expect(next.consumedNonces[liveKey]).toBe("2026-10-10T00:02:00.000Z");
    expect(Object.keys(next.consumedNonces)).toHaveLength(2);
    expect(Object.keys(initial.consumedNonces)).toHaveLength(2);
  });

  it("fails closed at the live-window cap without evicting a valid nonce", async () => {
    const live = Object.fromEntries(Array.from({ length: MAX_CONSUMED_MUTATION_NONCES }, (_, index) => [
      `0x${index.toString(16).padStart(64, "0")}`, "2026-10-10T00:02:00.000Z",
    ]));
    const initial = { workspace, consumedNonces: live };
    await expect(transitionSignedMutationState(initial, intent, signatureFor(intent), operation, now, resolver))
      .rejects.toBeInstanceOf(MutationNonceCapacityExceededError);
    expect(Object.keys(initial.consumedNonces)).toHaveLength(MAX_CONSUMED_MUTATION_NONCES);
    expect(initial.workspace.operations).toHaveLength(0);
  });

  it("checks a replay by key without scanning the retained window", async () => {
    const nonceKey = sha256Hex(JSON.stringify(["tr:mutation:nonce:v2", intent.registryId, actorDid, intent.nonce]));
    const live = new Proxy({ [nonceKey]: intent.expiresAt }, {
      ownKeys: () => { throw new Error("nonce lookup scanned all entries"); },
    });
    await expect(transitionSignedMutationState(
      { workspace, consumedNonces: live }, intent, signatureFor(intent), operation, now, resolver,
    )).rejects.toBeInstanceOf(MutationNonceAlreadyUsedError);
  });
});
