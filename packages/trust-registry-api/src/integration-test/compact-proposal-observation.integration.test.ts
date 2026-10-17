import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  computeCreateEvidenceVerifierKeyPayloadHash,
  computeRotateEvidenceVerifierKeyPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  EvidenceVerifierKeyStatus,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { labelToBytes32 } from "@midnight-ntwrk/trust-registry-contract/testing";

import {
  bytes32Commitment,
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  resolveCompactProposalEvidenceSnapshot,
  resolveCompactProposalObservation,
  type ProposalRole,
} from "../compact-proposal-observation.js";
import { createTrustRegistryApiServer } from "../server.js";

describe("finalized Compact proposal observation", () => {
  it.each(["issuer", "verifier", "auditor", "maintainer", "recognition"] as const)(
    "projects the immutable %s evidence and the registered verifier key",
    async (role: ProposalRole) => {
      const harness = new LocalTrustRegistryIntegrationHarness(`proposal-snapshot-${role}`);
      const fixture = role === "issuer" ? createIssuerScenarioFixture("snapshot")
        : role === "verifier" ? createVerifierScenarioFixture("snapshot")
          : role === "auditor" ? createAuditorScenarioFixture("snapshot")
            : role === "maintainer" ? createMaintainerScenarioFixture("snapshot")
              : createRecognitionScenarioFixture("snapshot");
      const id = "maintainerId" in fixture ? fixture.maintainerId
        : "recognitionId" in fixture ? fixture.recognitionId : fixture.authorizationId;
      const read = async () => harness.simulator.getLedger();
      expect(await resolveCompactProposalEvidenceSnapshot(read, harness.registryId, role, id)).toBeNull();
      if (role === "issuer") harness.proposeIssuer(fixture as ReturnType<typeof createIssuerScenarioFixture>);
      else if (role === "verifier") harness.proposeVerifier(fixture as ReturnType<typeof createVerifierScenarioFixture>);
      else if (role === "auditor") harness.proposeAuditor(fixture as ReturnType<typeof createAuditorScenarioFixture>);
      else if (role === "maintainer") harness.proposeMaintainer(fixture as ReturnType<typeof createMaintainerScenarioFixture>);
      else harness.proposeRecognition(fixture as ReturnType<typeof createRecognitionScenarioFixture>);
      const snapshot = await resolveCompactProposalEvidenceSnapshot(read, harness.registryId, role, id);
      expect(snapshot).toMatchObject({
        role,
        authorizationId: id,
        eventHash: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        evidenceCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        verifierAuthorizationId: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        verifierDidCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        verifierKeyIdCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        policyCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        policyVersion: expect.stringMatching(/^[1-9][0-9]*$/u),
        subjectDidCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        grantPolicyIdCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        proposedAtSequence: expect.stringMatching(/^[0-9]+$/u),
        boundActionPayloadHash: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        signatureVerified: true,
      });
      expect(BigInt(snapshot!.verifierPublicKey.x)).toBeGreaterThan(0n);
      expect(BigInt(snapshot!.verifierSignature.response)).toBeGreaterThan(0n);
      const ledger = harness.simulator.getLedger();
      const mapName = `${role}ProposalEvidenceRecords`;
      const substituted = new Proxy(ledger, {
        get(target, property) {
          if (property !== mapName) return Reflect.get(target, property, target);
          const records = Reflect.get(target, property, target) as typeof ledger.issuerProposalEvidenceRecords;
          return new Proxy(records, {
            get(map, key) {
              if (key === "lookup") {
                return (recordId: Uint8Array) => ({ ...map.lookup(recordId), verifierSignatureResponse: 0n });
              }
              const value = Reflect.get(map, key, map);
              return typeof value === "function" ? value.bind(map) : value;
            },
          });
        },
      });
      await expect(resolveCompactProposalEvidenceSnapshot(
        async () => substituted, harness.registryId, role, id,
      )).rejects.toThrow("signature is invalid");
      expect(await resolveCompactProposalEvidenceSnapshot(read, harness.registryId, role, `${id}:other`)).toBeNull();
      await expect(resolveCompactProposalEvidenceSnapshot(read, "registry:wrong", role, id))
        .rejects.toThrow("different trust registry");
    },
  );

  it.each(["issuer", "verifier", "auditor", "maintainer", "recognition"] as const)(
    "recovers a lost %s receipt from proposal evidence, not a process-local flag",
    async (role: ProposalRole) => {
      const harness = new LocalTrustRegistryIntegrationHarness(`proposal-observation-${role}`);
      const fixture = role === "issuer" ? createIssuerScenarioFixture("observation")
        : role === "verifier" ? createVerifierScenarioFixture("observation")
          : role === "auditor" ? createAuditorScenarioFixture("observation")
            : role === "maintainer" ? createMaintainerScenarioFixture("observation")
              : createRecognitionScenarioFixture("observation");
      const id = "maintainerId" in fixture ? fixture.maintainerId
        : "recognitionId" in fixture ? fixture.recognitionId : fixture.authorizationId;
      const read = async () => harness.simulator.getLedger();

      expect(await resolveCompactProposalObservation(read, harness.registryId, role, id)).toBeNull();
      const eventHash = role === "issuer" ? harness.proposeIssuer(fixture as ReturnType<typeof createIssuerScenarioFixture>)
        : role === "verifier" ? harness.proposeVerifier(fixture as ReturnType<typeof createVerifierScenarioFixture>)
          : role === "auditor" ? harness.proposeAuditor(fixture as ReturnType<typeof createAuditorScenarioFixture>)
            : role === "maintainer" ? harness.proposeMaintainer(fixture as ReturnType<typeof createMaintainerScenarioFixture>)
              : harness.proposeRecognition(fixture as ReturnType<typeof createRecognitionScenarioFixture>);
      const observed = await resolveCompactProposalObservation(read, harness.registryId, role, id);
      expect(observed?.eventHash).toBe(`0x${Buffer.from(eventHash).toString("hex")}`);
      expect(observed?.evidenceCommitment).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(await resolveCompactProposalObservation(read, harness.registryId, role, `${id}:other`)).toBeNull();
      for (const otherRole of ["issuer", "verifier", "auditor", "maintainer", "recognition"] as const) {
        if (otherRole !== role) {
          expect(await resolveCompactProposalObservation(read, harness.registryId, otherRole, id)).toBeNull();
        }
      }
    },
  );

  it("does not turn an unavailable finalized ledger into a retry-safe absence", async () => {
    await expect(resolveCompactProposalObservation(async () => {
      throw new Error("finality source unavailable");
    }, "registry:test", "issuer", "candidate")).rejects.toThrow("finality source unavailable");
  });

  it("retains proposal evidence after a later lifecycle action changes the authorization evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("proposal-history-after-suspension");
    const issuer = createIssuerScenarioFixture("history-after-suspension");
    harness.proposeIssuer(issuer);
    const read = async () => harness.simulator.getLedger();
    const proposal = await resolveCompactProposalEvidenceSnapshot(read, harness.registryId, "issuer", issuer.authorizationId);
    harness.approveIssuer(issuer);
    harness.activateIssuer(issuer);
    harness.suspendIssuer(issuer);
    expect(harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment).evidenceHash)
      .not.toEqual(harness.simulator.getLedger().issuerProposalEvidenceRecords.lookup(
        issuer.authorizationIdCommitment,
      ).evidenceCommitment);
    expect(await resolveCompactProposalEvidenceSnapshot(read, harness.registryId, "issuer", issuer.authorizationId))
      .toEqual(proposal);
  });

  it("rejects an indexer view that substitutes an immutable authorization subject", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("proposal-snapshot-mismatch");
    const issuer = createIssuerScenarioFixture("snapshot-mismatch");
    harness.proposeIssuer(issuer);
    const ledger = harness.simulator.getLedger();
    const records = ledger.issuerAuthorizationRecords;
    const substituted = new Proxy(records, {
      get(target, property) {
        if (property === "lookup") {
          return (id: Uint8Array) => ({ ...target.lookup(id), subjectDidCommitment: bytes32Commitment("did:midnight:other") });
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await expect(resolveCompactProposalEvidenceSnapshot(async () => ({
      ...ledger, issuerAuthorizationRecords: substituted,
    }), harness.registryId, "issuer", issuer.authorizationId)).rejects.toThrow("signature is invalid");
  });

  it("verifies every historical proposal role after its verifier key is retired", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("proposal-key-rotation-history");
    const signer = createMaintainerScenarioFixture("proposal-key-rotation-signer");
    harness.authorizeMaintainer(signer);
    const issuer = createIssuerScenarioFixture("key-rotation-history");
    const verifier = createVerifierScenarioFixture("key-rotation-history");
    const auditor = createAuditorScenarioFixture("key-rotation-history");
    const maintainer = createMaintainerScenarioFixture("key-rotation-history");
    const recognition = createRecognitionScenarioFixture("key-rotation-history");
    harness.proposeIssuer(issuer);
    harness.proposeVerifier(verifier);
    harness.proposeAuditor(auditor);
    harness.proposeMaintainer(maintainer);
    harness.proposeRecognition(recognition);
    const proposals = [
      ["issuer", issuer.authorizationId],
      ["verifier", verifier.authorizationId],
      ["auditor", auditor.authorizationId],
      ["maintainer", maintainer.maintainerId],
      ["recognition", recognition.recognitionId],
    ] as const;
    const read = async () => harness.simulator.getLedger();
    const before = await Promise.all(proposals.map(async ([role, id]) => {
      const snapshot = await resolveCompactProposalEvidenceSnapshot(read, harness.registryId, role, id);
      expect(snapshot?.signatureVerified).toBe(true);
      return snapshot;
    }));
    const ledger = harness.simulator.getLedger();
    const oldId = ledger.issuerProposalEvidenceRecords.lookup(issuer.authorizationIdCommitment)
      .evidenceVerifierAuthorizationId;
    const oldKey = ledger.evidenceVerifierKeyRecords.lookup(oldId);
    const newId = bytes32Commitment("historical-evidence-verifier-replacement");
    const newKeyId = bytes32Commitment("historical-evidence-verifier-replacement#assertion-1");
    const newPublicKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(91));
    const reason = bytes32Commitment("evidence-verifier-rotation");
    const nextPayload = computeCreateEvidenceVerifierKeyPayloadHash(
      newId, oldKey.verifierDidCommitment, newKeyId, newPublicKey,
      oldKey.suite, oldKey.policyCommitment, oldKey.policyVersion,
    );
    const actionPayload = computeRotateEvidenceVerifierKeyPayloadHash(
      oldId, oldKey.lifecycleEventHash, nextPayload, reason,
    );
    const signature = signDeploymentBoundMaintainerActionFromSeed(
      signer.seed, ledger.registryId, ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"), ledger.governancePolicyCommitment,
      labelToBytes32("tr:evidence-verifier:rotate"), actionPayload, ledger.governanceActionCount,
    );
    harness.simulator.rotateEvidenceVerifierKey(
      signer.keyId, deriveJubjubPublicKeyFromSeed(signer.seed), signature,
      oldId, newId, newKeyId, newPublicKey, reason,
    );
    expect(harness.simulator.getLedger().evidenceVerifierKeyRecords.lookup(oldId).status)
      .toBe(EvidenceVerifierKeyStatus.retired);
    for (const [index, [role, id]] of proposals.entries()) {
      expect(before[index]?.verifierAuthorizationId).toBe(`0x${Buffer.from(oldId).toString("hex")}`);
      expect(await resolveCompactProposalEvidenceSnapshot(read, harness.registryId, role, id))
        .toEqual(before[index]);
    }
    const rotatedLedger = harness.simulator.getLedger();
    const keyRecords = new Proxy(rotatedLedger.evidenceVerifierKeyRecords, {
      get(target, property) {
        if (property === "lookup") {
          return (id: Uint8Array) => ({ ...target.lookup(id), publicKey: newPublicKey });
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    for (const [role, id] of proposals) {
      await expect(resolveCompactProposalEvidenceSnapshot(async () => ({
        ...rotatedLedger, evidenceVerifierKeyRecords: keyRecords,
      }), harness.registryId, role, id)).rejects.toThrow("signature is invalid");
    }
  });

  it("rejects an unknown runtime role rather than reading recognition records", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("proposal-invalid-role");
    await expect(resolveCompactProposalObservation(
      async () => harness.simulator.getLedger(), harness.registryId, "other" as ProposalRole, "candidate",
    )).rejects.toThrow("Invalid proposal role");
  });

  it("waits for the supplied finalized view rather than reporting an unfinalized simulator write", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("proposal-finality-lag");
    const issuer = createIssuerScenarioFixture("finality-lag");
    let finalized = harness.simulator.getLedger();
    const read = async () => finalized;
    const eventHash = harness.proposeIssuer(issuer);

    expect(await resolveCompactProposalObservation(read, harness.registryId, "issuer", issuer.authorizationId)).toBeNull();
    finalized = harness.simulator.getLedger();
    expect(await resolveCompactProposalObservation(read, harness.registryId, "issuer", issuer.authorizationId)).toEqual({
      eventHash: `0x${Buffer.from(eventHash).toString("hex")}`,
      evidenceCommitment: `0x${Buffer.from(finalized.issuerProposalEvidenceRecords.lookup(
        issuer.authorizationIdCommitment,
      ).evidenceCommitment).toString("hex")}`,
    });
    await expect(resolveCompactProposalObservation(read, "registry:wrong:trusted", "issuer", issuer.authorizationId))
      .rejects.toThrow("different trust registry");
  });

  it("serves proposal snapshots only from the injected finalized view", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("proposal-snapshot-http");
    const issuer = createIssuerScenarioFixture("snapshot-http");
    let finalized = harness.simulator.getLedger();
    const source = { mode: "memory" as const,
      loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "proposal-snapshot-http" }) };
    let failRead = false;
    const server = createTrustRegistryApiServer({
      source,
      readFinalizedProposalLedger: async () => {
        if (failRead) throw new Error("private indexer diagnostic");
        return finalized;
      },
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener unavailable");
      const url = `http://127.0.0.1:${address.port}/v1/governed/issuer/${encodeURIComponent(issuer.authorizationId)}/proposal/evidence`;
      expect((await fetch(url)).status).toBe(404);
      harness.proposeIssuer(issuer);
      expect((await fetch(url)).status).toBe(404);
      finalized = harness.simulator.getLedger();
      const response = await fetch(url);
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(await response.json()).toMatchObject({
        role: "issuer",
        authorizationId: issuer.authorizationId,
        policyCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      });
      expect((await fetch(url.replace("/issuer/", "/other/"))).status).toBe(400);
      expect((await fetch(url.replace("/issuer/", "/verifier/"))).status).toBe(404);
      expect((await fetch(`http://127.0.0.1:${address.port}/v1/governed/issuer/${"x".repeat(257)}/proposal/evidence`)).status)
        .toBe(400);
      failRead = true;
      const failed = await fetch(url);
      expect(failed.status).toBe(503);
      expect(JSON.stringify(await failed.json())).not.toContain("private indexer diagnostic");
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
    const unavailable = createTrustRegistryApiServer({ source });
    await new Promise<void>((resolve) => unavailable.listen(0, "127.0.0.1", resolve));
    try {
      const address = unavailable.address();
      if (address === null || typeof address === "string") throw new Error("API listener unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/issuer/${encodeURIComponent(issuer.authorizationId)}/proposal/evidence`);
      expect(response.status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => unavailable.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("keeps recognition proposal evidence behind the private accreditation gate", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recognition-proposal-evidence-private");
    const recognition = createRecognitionScenarioFixture("private-proposal-evidence");
    harness.proposeRecognition(recognition);
    const source = { mode: "memory" as const,
      loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "private-proposal-evidence" }) };
    const server = createTrustRegistryApiServer({
      source,
      readFinalizedProposalLedger: async () => harness.simulator.getLedger(),
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener unavailable");
      const url = `http://127.0.0.1:${address.port}/v1/governed/recognition/${encodeURIComponent(recognition.recognitionId)}/proposal/evidence`;
      const response = await fetch(url);
      expect(response.status).toBe(503);
      expect(response.headers.get("access-control-allow-origin")).toBeNull();
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
