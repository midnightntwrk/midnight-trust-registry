import { Buffer } from "node:buffer";

import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  computeMutationPayloadCommitment,
  mutationIntentDigestBytes,
  type MutationIntent,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import { MutationIntentOperationMismatchError } from "../mutation-intent-preflight.js";
import { MutationNonceAlreadyUsedError, transitionSignedMutationState } from "../signed-mutation-state.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const workspace = createOperatorWorkspace({ label: "signed-transition" });
const actorDid = createMidnightDid("signed-transition:applicant");
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
  scopeCommitment: `0x${"11".repeat(32)}`,
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
    const initial = { workspace, consumedNonces: [] } as const;
    const next = await transitionSignedMutationState(initial, intent, signatureFor(intent), operation, now, resolver);
    expect(next.workspace.operations).toHaveLength(1);
    expect(next.consumedNonces).toEqual([JSON.stringify([intent.registryId, actorDid, intent.nonce])]);
    expect(initial.workspace.operations).toHaveLength(0);
    expect(initial.consumedNonces).toHaveLength(0);

    const newRevision = { ...intent, expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(next.workspace) };
    await expect(transitionSignedMutationState(next, newRevision, signatureFor(newRevision), operation, now, resolver))
      .rejects.toBeInstanceOf(MutationNonceAlreadyUsedError);
    expect(next.consumedNonces).toHaveLength(1);
  });

  it("does not consume a nonce when signature or operation binding fails", async () => {
    const initial = { workspace, consumedNonces: [] } as const;
    await expect(transitionSignedMutationState(
      initial, intent, { ...signatureFor(intent), value: `0x${"00".repeat(96)}` }, operation, now, resolver,
    )).rejects.toBeInstanceOf(MutationIntentOperationMismatchError);
    await expect(transitionSignedMutationState(
      initial, intent, signatureFor(intent), { ...operation, label: "other" }, now, resolver,
    )).rejects.toBeInstanceOf(MutationIntentOperationMismatchError);
    expect(initial.consumedNonces).toHaveLength(0);
    expect(initial.workspace.operations).toHaveLength(0);
  });
});
