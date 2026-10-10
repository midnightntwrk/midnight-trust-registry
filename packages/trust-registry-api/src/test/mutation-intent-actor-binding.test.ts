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

import { preflightMutationIntentActor } from "../mutation-intent-actor-binding.js";
import { MutationIntentDidResolutionUnavailableError } from "../mutation-intent-verifier.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const workspace = createOperatorWorkspace({ label: "actor-binding" });
const applicantDid = createMidnightDid("actor-binding:applicant");
const maintainerDid = workspace.snapshot.registry.maintainerDids[0];
if (maintainerDid === undefined) throw new Error("missing bootstrap maintainer");
const seed = new Uint8Array(32).fill(91);
const payload = { target: "issuer", label: "example" };
const now = new Date("2026-10-10T00:01:00.000Z");

const intent: MutationIntent = {
  version: "tr-mutation-intent-v1",
  registryId: workspace.snapshot.registry.registryId,
  actorDid: applicantDid,
  actorKeyId: `${applicantDid}#assertion-1`,
  actorRole: "applicant",
  action: "submit",
  target: "issuer",
  targetId: "auth:issuer:example:v1",
  scopeCommitment: `0x${"11".repeat(32)}`,
  payloadCommitment: computeMutationPayloadCommitment(payload),
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
    seed,
    mutationIntentDigestBytes(value),
  ))).toString("hex")}`,
});

const resolverFor = (did: string) => createMidnightDidResolver([
  createMidnightDidLedgerFixture(did, {
    verificationMethodId: "assertion-1",
    schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
    capabilityInvocation: true,
  }),
]);

describe("mutation intent actor preflight", () => {
  it("accepts a valid applicant signature without granting maintainer authority", async () => {
    expect(await preflightMutationIntentActor(
      intent, signatureFor(intent), payload, workspace, now, resolverFor(applicantDid),
    )).toEqual({ ok: true, intent });

    const forgedMaintainer: MutationIntent = { ...intent, actorRole: "maintainer", action: "approve" };
    expect(await preflightMutationIntentActor(
      forgedMaintainer, signatureFor(forgedMaintainer), payload, workspace, now, resolverFor(applicantDid),
    )).toEqual({ ok: false, reason: "not-maintainer" });
  });

  it("accepts a listed maintainer only with a matching DID capability key", async () => {
    const governedPayload = { target: "issuer", id: intent.targetId };
    const governed: MutationIntent = {
      ...intent,
      actorDid: maintainerDid,
      actorKeyId: `${maintainerDid}#assertion-1`,
      actorRole: "maintainer",
      action: "approve",
      payloadCommitment: computeMutationPayloadCommitment(governedPayload),
    };
    const resolver = resolverFor(maintainerDid);
    expect(await preflightMutationIntentActor(
      governed, signatureFor(governed), governedPayload, workspace, now, resolver,
    )).toEqual({ ok: true, intent: governed });
    expect(await preflightMutationIntentActor(
      governed, { ...signatureFor(governed), value: `0x${"00".repeat(96)}` },
      governedPayload, workspace, now, resolver,
    )).toEqual({ ok: false, reason: "invalid-signature" });
    expect(await preflightMutationIntentActor(
      governed, signatureFor(governed), { ...governedPayload, id: "other" }, workspace, now, resolver,
    )).toEqual({ ok: false, reason: "wrong-payload" });
  });

  it("preserves retryable resolver failures", async () => {
    await expect(preflightMutationIntentActor(
      intent, signatureFor(intent), payload, workspace, now,
      { resolveResult: async () => { throw new Error("RPC unavailable"); } },
    )).rejects.toBeInstanceOf(MutationIntentDidResolutionUnavailableError);
  });
});
