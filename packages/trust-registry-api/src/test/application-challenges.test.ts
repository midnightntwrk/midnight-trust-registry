import { describe, expect, it, vi } from "vitest";
import {
  assertValidApplicationEvidence,
  computeApplicationEvidenceCommitment,
  computeAuthorizationScopeCommitment,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  ApplicationChallengeCapacityError,
  ApplicationChallengeService,
  InMemoryApplicationChallengeStore,
  type ApplicationChallengeBinding,
  type ApplicationChallengeRecord,
  type ApplicationChallengeStore,
} from "../application-challenges.js";

const scope = {
  version: "tr-scope-v1",
  role: "issuer",
  credentialFamilyId: "credential-family:organization",
  schemaId: "schema:organization",
  schemaVersion: "1.0.0",
  credentialDefinitionId: "credential-definition:organization",
  statusMethod: "midnight-status-registry-v1",
} as const;

const binding: ApplicationChallengeBinding = {
  registryId: "registry:kanon:trusted",
  applicationId: "application:issuer:one",
  subjectDid: "did:midnight:issuer:one",
  evidenceVerifierDid: "did:midnight:evidence-verifier:one",
  role: "issuer",
  policyId: "policy:kanon:v1",
  policyVersion: "v1",
  scope,
  scopeCommitment: computeAuthorizationScopeCommitment(scope),
  governedResource: { type: "credentialFamily", id: scope.credentialFamilyId },
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
    const underlying = new InMemoryApplicationChallengeStore();
    const yieldingStore: ApplicationChallengeStore = {
      insert: (record, nowMs) => underlying.insert(record, nowMs),
      consume: async (challengeHash, bindingHash, nowMs) => {
        await Promise.resolve();
        return underlying.consume(challengeHash, bindingHash, nowMs);
      },
    };
    const service = new ApplicationChallengeService(yieldingStore, () => START);
    const issued = await service.issue(binding);
    const input = { binding, nonce: issued.nonce, challengeHash: issued.challengeHash };

    const results = await Promise.all([service.consume(input), service.consume(input)]);
    expect(results).toContain(null);
    expect(results).toContain(issued.challengeHash);
    expect(await service.consume(input)).toBeNull();
  });

  it("supersedes the prior live challenge for the same binding", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const first = await service.issue(binding);
    const second = await service.issue(binding);

    expect(await service.consume({ binding, nonce: first.nonce, challengeHash: first.challengeHash })).toBeNull();
    expect(await service.consume({ binding, nonce: second.nonce, challengeHash: second.challengeHash })).toBe(second.challengeHash);
  });

  it("keeps distinct full bindings live even when the application id matches", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const otherScope = { ...scope, schemaVersion: "2.0.0" };
    const otherBinding = { ...binding, scope: otherScope, scopeCommitment: computeAuthorizationScopeCommitment(otherScope) };
    const first = await service.issue(binding);
    const second = await service.issue(otherBinding);
    expect(await service.consume({ binding, nonce: first.nonce, challengeHash: first.challengeHash })).toBe(first.challengeHash);
    expect(await service.consume({ binding: otherBinding, nonce: second.nonce, challengeHash: second.challengeHash })).toBe(second.challengeHash);
  });

  it("checks every issuer resource type without replacing the scope commitment", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const resources = [
      { type: "credentialFamily", id: scope.credentialFamilyId },
      { type: "schema", id: scope.schemaId },
      { type: "schemaVersion", id: scope.schemaVersion },
      { type: "credentialDefinition", id: scope.credentialDefinitionId },
      { type: "statusMethodRequirement", id: scope.statusMethod },
    ] as const;
    for (const governedResource of resources) {
      const scopedBinding = { ...binding, governedResource };
      const issued = await service.issue(scopedBinding);
      expect(await service.consume({
        binding: { ...scopedBinding, governedResource: { ...governedResource, id: "other-resource" } },
        nonce: issued.nonce,
        challengeHash: issued.challengeHash,
      })).toBeNull();
      expect(await service.consume({ binding: scopedBinding, nonce: issued.nonce, challengeHash: issued.challengeHash }))
        .toBe(issued.challengeHash);
    }
  });

  it.each(["verifier", "auditor"] as const)("checks %s request-profile resource independently of scope hash", async (role) => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const requestScope = {
      version: "tr-scope-v1" as const,
      role,
      requestProfileId: "request-profile:admission",
      purpose: "admission",
      credentialScopeCommitment: binding.scopeCommitment,
      allowedAttributes: ["degree"],
      allowedPredicates: ["age-over-18"],
      disclosureLevel: "minimum",
    };
    const requestBinding = {
      ...binding,
      role,
      scope: requestScope,
      scopeCommitment: computeAuthorizationScopeCommitment(requestScope),
      governedResource: { type: "requestProfile" as const, id: requestScope.requestProfileId },
    };
    const issued = await service.issue(requestBinding);
    expect(await service.consume({
      binding: { ...requestBinding, governedResource: { type: "requestProfile", id: "request-profile:other" } },
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBeNull();
    expect(await service.consume({ binding: requestBinding, nonce: issued.nonce, challengeHash: issued.challengeHash }))
      .toBe(issued.challengeHash);
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

    const consumedChallengeHash = await service.consume({ binding, nonce: issued.nonce, challengeHash: envelope.challengeHash });
    expect(consumedChallengeHash).toBe(issued.challengeHash);
    if (consumedChallengeHash === null) throw new Error("expected a consumed challenge");
    expect(() => assertValidApplicationEvidence(
      submission,
      { ...binding, evaluatedAt: "2026-10-06T00:00:00Z", challengeHash: consumedChallengeHash },
      [{ did: binding.evidenceVerifierDid, keyIds: [submission.signature.keyId], algorithms: ["jubjub-schnorr"] }],
      () => true,
    )).not.toThrow();
    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: envelope.challengeHash })).toBeNull();
  });

  it("accepts envelope-compatible hex case and non-Midnight verifier DIDs", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const webBinding = {
      ...binding,
      evidenceVerifierDid: "did:web:verifier.example",
    };
    const issued = await service.issue(webBinding);
    const envelopeHash = `0x${issued.challengeHash.slice(2).toUpperCase()}`;

    const consumedChallengeHash = await service.consume({
      binding: { ...webBinding, scopeCommitment: webBinding.scopeCommitment.toUpperCase().replace(/^0X/, "0x") },
      nonce: issued.nonce,
      challengeHash: envelopeHash,
    });
    expect(consumedChallengeHash).toBe(issued.challengeHash);
    if (consumedChallengeHash === null) throw new Error("expected a consumed challenge");

    const envelope = {
      version: "tr-application-evidence-v1" as const,
      ...webBinding,
      challengeHash: envelopeHash,
      verifiedAt: "2026-10-06T00:00:00Z",
      expiresAt: "2026-10-07T00:00:00Z",
      presentationHash: `0x${"2".repeat(64)}`,
      claimsCommitment: `0x${"3".repeat(64)}`,
    };
    const keyId = `${webBinding.evidenceVerifierDid}#assertion-1`;
    expect(() => assertValidApplicationEvidence(
      {
        envelope,
        commitment: computeApplicationEvidenceCommitment(envelope),
        signature: { keyId, algorithm: "jubjub-schnorr", value: "fixture-signature" },
      },
      { ...webBinding, challengeHash: consumedChallengeHash, evaluatedAt: "2026-10-06T00:00:00Z" },
      [{ did: webBinding.evidenceVerifierDid, keyIds: [keyId], algorithms: ["jubjub-schnorr"] }],
      () => true,
    )).not.toThrow();
  });

  it("prunes expired in-memory records on a subsequent issuance", async () => {
    const store = new InMemoryApplicationChallengeStore();
    const record = {
      challengeHash: `0x${"a".repeat(64)}`,
      bindingHash: `0x${"b".repeat(64)}`,
      expiresAtMs: START + 1,
    };
    expect(await store.insert(record, START)).toBe(true);
    expect(await store.insert(record, START)).toBe(false);
    expect(await store.insert({ ...record, expiresAtMs: START + 2 }, START + 1)).toBe(true);
  });

  it("bounds live entries and reclaims expired records without a later request", async () => {
    const store = new InMemoryApplicationChallengeStore(1);
    const service = new ApplicationChallengeService(store, () => START);
    const first = await service.issue(binding);
    const otherBinding = { ...binding, applicationId: "application:issuer:two" };
    await expect(service.issue(otherBinding)).rejects.toThrow(ApplicationChallengeCapacityError);
    expect(await service.consume({ binding, nonce: first.nonce, challengeHash: first.challengeHash })).toBe(first.challengeHash);
    expect((await service.issue(otherBinding)).challengeHash).toMatch(/^0x[0-9a-f]{64}$/);

    vi.useFakeTimers();
    try {
      const idleStore = new InMemoryApplicationChallengeStore(1);
      const idleService = new ApplicationChallengeService(idleStore, () => START);
      const idle = await idleService.issue(binding);
      await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
      expect(await idleService.consume({ binding, nonce: idle.nonce, challengeHash: idle.challengeHash })).toBeNull();
      expect((await idleService.issue(otherBinding)).challengeHash).toMatch(/^0x[0-9a-f]{64}$/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects invalid capacity and expiry outside the timer range", async () => {
    for (const capacity of [0, -1, 1.5]) {
      expect(() => new InMemoryApplicationChallengeStore(capacity)).toThrow(/capacity is invalid/);
    }
    const store = new InMemoryApplicationChallengeStore();
    await expect(store.insert({
      challengeHash: `0x${"a".repeat(64)}`,
      bindingHash: `0x${"b".repeat(64)}`,
      expiresAtMs: START + 2_147_483_648,
    }, START)).rejects.toThrow(/timer range/);
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

    expect(await service.consume({ ...input, binding: { ...binding, ...change } })).toBeNull();
    expect(await service.consume({ ...input, binding })).toBe(issued.challengeHash);
  });

  it("rejects a wrong envelope hash or noncanonical nonce without consuming", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);

    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: `0x${"0".repeat(64)}` })).toBeNull();
    expect(await service.consume({ binding, nonce: issued.nonce.toUpperCase(), challengeHash: issued.challengeHash })).toBeNull();
    expect(await service.consume({ binding: { ...binding, subjectDid: "not-a-did" }, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBeNull();
    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(issued.challengeHash);
  });

  it("rejects a challenge at its expiry boundary", async () => {
    let now = START;
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => now);
    const issued = await service.issue(binding);
    now += 5 * 60 * 1000;

    expect(await service.consume({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBeNull();
  });

  it("rejects invalid clock values and invalid application bindings", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => Number.NaN);
    await expect(service.issue(binding)).rejects.toThrow(/clock is invalid/);

    let now = START;
    const consumingService = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => now);
    const issued = await consumingService.issue(binding);
    now = Number.NaN;
    await expect(consumingService.consume({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).rejects.toThrow(/clock is invalid/);
    now = START;
    expect(await consumingService.consume({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(issued.challengeHash);

    const valid = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    await expect(valid.issue({ ...binding, scopeCommitment: "not-a-hash" })).rejects.toThrow();
    await expect(valid.issue({ ...binding, policyVersion: " v1 " })).rejects.toThrow();
    await expect(valid.issue({ ...binding, policyVersion: "1.0.0" })).rejects.toThrow();
  });

  it("binds the canonical role-specific scope rather than trusting an opaque digest", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const reorderedScope = {
      role: scope.role,
      version: scope.version,
      statusMethod: scope.statusMethod,
      credentialDefinitionId: scope.credentialDefinitionId,
      schemaVersion: scope.schemaVersion,
      schemaId: scope.schemaId,
      credentialFamilyId: scope.credentialFamilyId,
    };
    expect(await service.consume({
      binding: { ...binding, scope: reorderedScope },
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBe(issued.challengeHash);

    await expect(service.issue({ ...binding, scope: { ...scope, schemaVersion: "2.0.0" } })).rejects.toThrow(/Scope commitment/);
    const verifierScope = {
      version: "tr-scope-v1" as const,
      role: "verifier" as const,
      requestProfileId: "request-profile:admission",
      purpose: "admission",
      credentialScopeCommitment: binding.scopeCommitment,
      allowedAttributes: ["degree"],
      allowedPredicates: ["age-over-18"],
      disclosureLevel: "minimum",
    };
    await expect(service.issue({
      ...binding,
      scope: verifierScope,
      scopeCommitment: computeAuthorizationScopeCommitment(verifierScope),
    })).rejects.toThrow(/Scope role/);
    await expect(service.issue({ ...binding, scope: { ...scope, schemaId: "schema:*" } })).rejects.toThrow();
    await expect(service.issue({ ...binding, scope: { ...scope, extra: "ignored" } as typeof scope })).rejects.toThrow();
  });

  it("rejects malformed nested scope on consume without throwing or consuming the challenge", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const malformed = {
      ...binding,
      scope: { ...scope, schemaId: "schema:*", schemaVersion: "1.0" },
    } as unknown as ApplicationChallengeBinding;

    expect(await service.consume({
      binding: malformed,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBeNull();
    expect(await service.consume({
      binding: { ...binding, scopeCommitment: null } as unknown as ApplicationChallengeBinding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBeNull();
    expect(await service.consume({
      binding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBe(issued.challengeHash);
  });

  it("binds maintainer scope to the same registry as the challenge", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const maintainerScope = {
      version: "tr-scope-v1" as const,
      role: "maintainer" as const,
      registryId: binding.registryId,
    };
    const maintainerBinding = {
      ...binding,
      role: "maintainer" as const,
      scope: maintainerScope,
      scopeCommitment: computeAuthorizationScopeCommitment(maintainerScope),
      governedResource: { type: "registry" as const, id: maintainerScope.registryId },
    };
    const issued = await service.issue(maintainerBinding);
    await expect(service.issue({
      ...maintainerBinding,
      registryId: "Registry:Kanon:Trusted",
    })).rejects.toThrow(/canonical lowercase/i);
    await expect(service.issue({
      ...binding,
      registryId: "Registry:Kanon:Trusted",
    })).rejects.toThrow(/canonical lowercase/i);
    const wrongRegistryScope = {
      ...maintainerScope,
      registryId: "registry:other:trusted",
    };
    const wrongRegistryBinding = {
      ...maintainerBinding,
      scope: wrongRegistryScope,
      scopeCommitment: computeAuthorizationScopeCommitment(wrongRegistryScope),
    };

    await expect(service.issue(wrongRegistryBinding)).rejects.toThrow(/Maintainer scope registry/);
    expect(await service.consume({
      binding: wrongRegistryBinding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBeNull();
    expect(await service.consume({
      binding: maintainerBinding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBe(issued.challengeHash);
  });

  it("rejects case variants of challenge identifiers without creating parallel live challenges", async () => {
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    for (const changed of [
      { applicationId: "Application:Issuer:One" },
      { policyId: "Policy:Kanon:V1" },
    ]) {
      await expect(service.issue({ ...binding, ...changed })).rejects.toThrow(/canonical lowercase/i);
      expect(await service.consume({
        binding: { ...binding, ...changed },
        nonce: issued.nonce,
        challengeHash: issued.challengeHash,
      })).toBeNull();
    }
    expect(await service.consume({
      binding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
    })).toBe(issued.challengeHash);
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
