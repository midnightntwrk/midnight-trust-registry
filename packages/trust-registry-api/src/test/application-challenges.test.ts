import { describe, expect, it } from "vitest";
import {
  assertValidApplicationEvidence,
  computeApplicationEvidenceCommitment,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  ApplicationChallengeService,
  InMemoryApplicationChallengeStore,
  type ApplicationChallengeBinding,
  type ApplicationChallengeRecord,
  type ApplicationChallengeStore,
} from "../application-challenges.js";

const binding: ApplicationChallengeBinding = {
  registryId: "registry:kanon:trusted",
  applicationId: "application:issuer:one",
  subjectDid: "did:midnight:issuer:one",
  evidenceVerifierDid: "did:midnight:evidence-verifier:one",
  role: "issuer",
  policyId: "policy:kanon:v1",
  policyVersion: "v1",
  scopeCommitment: `0x${"1".repeat(64)}`,
};

const START = Date.parse("2026-10-06T00:00:00.000Z");

describe("application challenge lifecycle", () => {
  it("issues a random nonce but stores only its hash, binding hash, and expiry", async () => {
    const records: ApplicationChallengeRecord[] = [];
    const store: ApplicationChallengeStore = {
      insert: async (record) => {
        records.push(record);
        return true;
      },
      consume: async () => false,
    };
    const service = new ApplicationChallengeService(store, () => START);
    const first = await service.issue(binding);
    const second = await service.issue(binding);

    expect(first.nonce).toMatch(/^0x[0-9a-f]{64}$/);
    expect(first.challengeHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.issuedAt).toBe("2026-10-06T00:00:00.000Z");
    expect(first.expiresAt).toBe("2026-10-06T00:05:00.000Z");
    expect(records).toHaveLength(2);
    expect(records[0]).toEqual({
      challengeHash: first.challengeHash,
      bindingHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
      expiresAtMs: START + 5 * 60 * 1000,
    });
    expect(JSON.stringify(records)).not.toContain(first.nonce);
    expect(JSON.stringify(records)).not.toContain(binding.subjectDid);
  });

  it("accepts exactly one consumption even when submitted concurrently", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const input = { binding, nonce: issued.nonce, challengeHash: issued.challengeHash };

    const results = await Promise.all([service.consume(input), service.consume(input)]);
    expect(results.sort()).toEqual([false, true]);
    expect(await service.consume(input)).toBe(false);
  });

  it("binds an issued challenge to the evidence envelope before one-use consumption", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const envelope = {
      version: "tr-application-evidence-v1" as const,
      ...binding,
      verifiedAt: "2026-10-06T00:00:00Z",
      expiresAt: "2026-10-07T00:00:00Z",
      challengeHash: issued.challengeHash,
      presentationHash: `0x${"2".repeat(64)}`,
      claimsCommitment: `0x${"3".repeat(64)}`,
    };
    const submission = {
      envelope,
      commitment: computeApplicationEvidenceCommitment(envelope),
      signature: {
        keyId: `${binding.evidenceVerifierDid}#assertion-1`,
        algorithm: "jubjub-schnorr" as const,
        value: "fixture-signature",
      },
    };

    expect(() => assertValidApplicationEvidence(
      submission,
      { ...binding, evaluatedAt: "2026-10-06T00:00:00Z", challengeHash: issued.challengeHash },
      [{ did: binding.evidenceVerifierDid, keyIds: [submission.signature.keyId], algorithms: ["jubjub-schnorr"] }],
      () => true,
    )).not.toThrow();
    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: envelope.challengeHash })).toBe(true);
    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: envelope.challengeHash })).toBe(false);
  });

  it.each([
    ["registry", { registryId: "registry:other:trusted" }],
    ["application", { applicationId: "application:issuer:two" }],
    ["subject", { subjectDid: "did:midnight:issuer:two" }],
    ["evidence verifier", { evidenceVerifierDid: "did:midnight:evidence-verifier:two" }],
    ["role", { role: "verifier" as const }],
    ["policy", { policyId: "policy:other:v1" }],
    ["policy version", { policyVersion: "v2" }],
    ["scope", { scopeCommitment: `0x${"2".repeat(64)}` }],
  ])("rejects a changed %s without consuming the valid challenge", async (_label, change) => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const input = { nonce: issued.nonce, challengeHash: issued.challengeHash };

    expect(await service.consume({ ...input, binding: { ...binding, ...change } })).toBe(false);
    expect(await service.consume({ ...input, binding })).toBe(true);
  });

  it("rejects a wrong envelope hash or noncanonical nonce without consuming", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);

    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: `0x${"0".repeat(64)}` })).toBe(false);
    expect(await service.consume({ binding, nonce: issued.nonce.toUpperCase(), challengeHash: issued.challengeHash })).toBe(false);
    expect(await service.consume({ binding: { ...binding, subjectDid: "not-a-did" }, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(false);
    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(true);
  });

  it("rejects a challenge at its expiry boundary", async () => {
    let now = START;
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => now);
    const issued = await service.issue(binding);
    now += 5 * 60 * 1000;

    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(false);
  });

  it("rejects invalid clock values and invalid application bindings", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => Number.NaN);
    await expect(service.issue(binding)).rejects.toThrow(/clock is invalid/);

    const valid = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    await expect(valid.issue({ ...binding, scopeCommitment: "not-a-hash" })).rejects.toThrow();
  });

  it("fails closed if the store reports repeated challenge hash collisions", async () => {
    let attempts = 0;
    const store: ApplicationChallengeStore = {
      insert: async () => {
        attempts += 1;
        return false;
      },
      consume: async () => false,
    };
    const service = new ApplicationChallengeService(store, () => START);

    await expect(service.issue(binding)).rejects.toThrow(/Could not issue/);
    expect(attempts).toBe(3);
  });
});
