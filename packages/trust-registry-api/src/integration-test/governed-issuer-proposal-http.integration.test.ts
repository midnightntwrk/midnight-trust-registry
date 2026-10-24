import { Buffer } from "node:buffer";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signIssuerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  issuerResourceTypeDetails,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedIssuerProposalRejectedError,
  type GovernedIssuerProposalPort,
  type PreparedGovernedIssuerProposal,
} from "../governed-issuer-proposals.js";
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";
import { FileProposalSubmissionJournal } from "../proposal-submission-journal.js";
import { createTrustRegistryApiServer } from "../server.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedGovernedIssuerProposal,
) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    bytes(prepared.registryId),
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    bytes(prepared.policyCommitment),
    bytes(prepared.actionKind),
    bytes(prepared.actionPayloadHash),
    BigInt(prepared.actionSequence),
  );
  return {
    keyId: `0x${Buffer.from(maintainer.keyId).toString("hex")}`,
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`,
  };
};

describe("Compact-backed issuer proposals over HTTP", () => {
  it("does not resubmit after a lost Compact response and reconciles a finalized observation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("issuer-journal-http");
    const second = createMaintainerScenarioFixture("issuer-journal-second");
    const third = createMaintainerScenarioFixture("issuer-journal-third");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const issuer = createIssuerScenarioFixture("issuer-journal-candidate");
    const scope = createIssuerAuthorizationScopeFixture(issuer);
    const governedResource = { type: issuerResourceTypeDetails[issuer.resourceType].governedType, id: issuer.resourceId };
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope,
      governedResource,
    });
    const binding = {
      registryId: evidence.envelope.registryId,
      applicationId: evidence.envelope.applicationId,
      subjectDid: evidence.envelope.subjectDid,
      evidenceVerifierDid: evidence.envelope.evidenceVerifierDid,
      role: "issuer" as const,
      policyId: evidence.envelope.policyId,
      policyVersion: evidence.envelope.policyVersion,
      scope,
      scopeCommitment: evidence.envelope.scopeCommitment,
      governedResource,
    };
    const directory = await mkdtemp(join(tmpdir(), "tr-issuer-journal-http-"));
    const journalPath = join(directory, "journal.json");
    const journal = new FileProposalSubmissionJournal(journalPath);
    let finalizedLedger = harness.simulator.getLedger();
    let eventHash: string | undefined;
    let executions = 0;
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "journal" }) },
      proposalAdmission: {
        resolvePendingApplication: async () => ({
          authorizationId: issuer.authorizationId, binding, status: "pending", createdAt: "2026-05-20T00:00:00.000Z",
        }),
        resolveAcceptedEvidence: async () => ({
          evidence,
          receipt: { receiptId: `0x${"b2".repeat(32)}`, evidenceCommitment: evidence.commitment,
            acceptedAt: "2026-05-20T00:01:00.000Z" },
        }),
      },
      proposalSubmissionJournal: journal,
      governedIssuerProposals: {
        prepare: async () => harness.prepareIssuerProposalAction(issuer, evidence),
        execute: async (_, submitted, signers, verifierSignature) => {
          executions += 1;
          eventHash = `0x${Buffer.from(harness.executeIssuerProposalWithSignatures(
            issuer, submitted, signers, verifierSignature,
          )).toString("hex")}`;
          throw new Error("response lost after Compact submission");
        },
        resolve: async (authorizationId) => resolveCompactProposalObservation(
          async () => finalizedLedger, harness.registryId, "issuer", authorizationId,
        ),
      },
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/issuer/${issuer.authorizationId}/proposal`;
      const post = (action: "prepare" | "submit" | "resolve", body: unknown) => fetch(`${endpoint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const preparedResponse = await post("prepare", { evidence });
      expect(preparedResponse.status).toBe(200);
      const prepared = await preparedResponse.json() as PreparedGovernedIssuerProposal;
      const verifierSignature = harness.signIssuerProposalEvidence(harness.prepareIssuerProposalAction(issuer, evidence));
      const request = { evidence, prepared, signers: [signPrepared(harness, second, prepared), signPrepared(harness, third, prepared)],
        evidenceVerifierSignature: `0x${Buffer.from(encodeJubjubSignature(verifierSignature)).toString("hex")}` };
      const wrongSequence = { ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() };
      const forged = await post("submit", { ...request, signers: [signPrepared(harness, second, wrongSequence), request.signers[1]] });
      expect(forged.status).toBe(403);
      expect((await forged.json()).type).toMatch(/invalid-governed-signature$/u);
      expect(await journal.read("issuer", issuer.authorizationId)).toBeNull();
      expect(executions).toBe(0);
      const duplicateVotes = await post("submit", { ...request, signers: [request.signers[0], request.signers[0]] });
      expect(duplicateVotes.status).toBe(403);
      expect(await journal.read("issuer", issuer.authorizationId)).toBeNull();
      const uncertain = await post("submit", request);
      expect(uncertain.status).toBe(503);
      expect((await uncertain.json()).type).toMatch(/proposal-submission-uncertain$/u);
      expect(await journal.read("issuer", issuer.authorizationId)).toMatchObject({ state: "reserved", eventHash: null });
      expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(1n);
      const duplicate = await post("submit", request);
      expect(duplicate.status).toBe(409);
      expect(executions).toBe(1);
      expect(await (await post("resolve", { evidence })).json()).toEqual({ state: "not-observed" });
      finalizedLedger = harness.simulator.getLedger();
      expect(eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(await (await post("resolve", { evidence })).json()).toEqual({ state: "observed", eventHash });
      expect(await journal.read("issuer", issuer.authorizationId)).toMatchObject({ state: "observed", eventHash });
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("uses the bound reader, not the port resolver, for synthetic local-ledger readback", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("issuer-local-reader-route");
    const issuer = createIssuerScenarioFixture("issuer-local-reader-candidate");
    const scope = createIssuerAuthorizationScopeFixture(issuer);
    const governedResource = { type: issuerResourceTypeDetails[issuer.resourceType].governedType, id: issuer.resourceId };
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId, subjectDid: issuer.subjectDid,
      role: "issuer", scope, governedResource,
    });
    const binding = {
      registryId: evidence.envelope.registryId, applicationId: evidence.envelope.applicationId,
      subjectDid: evidence.envelope.subjectDid, evidenceVerifierDid: evidence.envelope.evidenceVerifierDid,
      role: "issuer" as const, policyId: evidence.envelope.policyId,
      policyVersion: evidence.envelope.policyVersion, scope,
      scopeCommitment: evidence.envelope.scopeCommitment, governedResource,
    };
    const directory = await mkdtemp(join(tmpdir(), "tr-local-reader-route-"));
    const contractAddress = `0x${harness.simulator.contractAddress}`;
    const genesisHash = `0x${"a".repeat(64)}`;
    const journalPath = join(directory, "journal.json");
    const journal = new FileProposalSubmissionJournal(journalPath);
    await journal.bindDeployment(harness.registryId, contractAddress, genesisHash);
    const reader = vi.fn(async () => harness.simulator.getLedger());
    const resolve = vi.fn(async () => { throw new Error("untrusted port resolver"); });
    const serverFor = (sourceGenesisHash: string) => createTrustRegistryApiServer({
      source: {
        mode: "local-ledger", localDeploymentBinding: { contractAddress, expectedGenesisHash: sourceGenesisHash },
        loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "synthetic-local-readback" }),
        readFinalizedProposalLedger: reader,
      },
      proposalAdmission: {
        resolvePendingApplication: async () => ({
          authorizationId: issuer.authorizationId, binding, status: "pending", createdAt: "2026-05-20T00:00:00.000Z",
        }),
        resolveAcceptedEvidence: async () => ({
          evidence, receipt: { receiptId: `0x${"b2".repeat(32)}`, evidenceCommitment: evidence.commitment,
            acceptedAt: "2026-05-20T00:01:00.000Z" },
        }),
      },
      proposalSubmissionJournal: journal,
      governedIssuerProposals: {
        prepare: async () => { throw new Error("unused"); },
        execute: async () => { throw new Error("unused"); },
        resolve,
      },
    });
    try {
      for (const [sourceGenesisHash, expectedStatus] of [
        [genesisHash, 200], [`0x${"c".repeat(64)}`, 409], [genesisHash, 503],
      ] as const) {
        const server = serverFor(sourceGenesisHash);
        try {
          await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
          const address = server.address();
          if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
          if (expectedStatus === 503) reader.mockRejectedValueOnce(new Error("secret-provider-credential"));
          const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/issuer/${issuer.authorizationId}/proposal/resolve`, {
            method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ evidence }),
          });
          expect(response.status).toBe(expectedStatus);
          if (expectedStatus === 200) expect(await response.json()).toEqual({ state: "not-observed" });
          if (expectedStatus === 503) expect(await response.text()).not.toContain("secret-provider-credential");
        } finally {
          server.closeAllConnections();
          await new Promise<void>((ready, reject) => server.close((error) => error ? reject(error) : ready()));
        }
      }
      expect(reader).toHaveBeenCalledTimes(2);
      expect(resolve).not.toHaveBeenCalled();
      await chmod(`${journalPath}.binding`, 0o644);
      const server = serverFor(genesisHash);
      try {
        await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
        const address = server.address();
        if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
        const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/issuer/${issuer.authorizationId}/proposal/resolve`, {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ evidence }),
        });
        expect(response.status).toBe(503);
        expect((await response.json()).type).toMatch(/proposal-submission-journal-unavailable$/u);
      } finally {
        server.closeAllConnections();
        await new Promise<void>((ready, reject) => server.close((error) => error ? reject(error) : ready()));
      }
      expect(reader).toHaveBeenCalledTimes(2);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("requires an injected proposal port", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("issuer-proposal-unavailable");
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "unavailable" }) },
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/issuer/app/proposal/prepare`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      expect(response.status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("binds signed application evidence, a registered verifier key, and 2-of-3 external maintainers", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("issuer-proposal-http");
    const second = createMaintainerScenarioFixture("issuer-proposal-second");
    const third = createMaintainerScenarioFixture("issuer-proposal-third");
    const issuer = createIssuerScenarioFixture("issuer-proposal-candidate");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: issuerResourceTypeDetails[issuer.resourceType].governedType, id: issuer.resourceId },
    });
    const port: GovernedIssuerProposalPort = {
      async prepare(authorizationId, submitted) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerProposalRejectedError("unknown-authorization");
        }
        try {
          return harness.prepareIssuerProposalAction(issuer, submitted);
        } catch {
          throw new GovernedIssuerProposalRejectedError("invalid-evidence");
        }
      },
      async execute(authorizationId, submitted, signers, verifierSignature) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerProposalRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeIssuerProposalWithSignatures(issuer, submitted, signers, verifierSignature);
        } catch {
          throw new GovernedIssuerProposalRejectedError("invalid-signers");
        }
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
      async resolve(authorizationId) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerProposalRejectedError("unknown-authorization");
        }
        return resolveCompactProposalObservation(async () => harness.simulator.getLedger(),
          harness.registryId, "issuer", authorizationId);
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness,
        { label: "issuer-proposal-http", issuers: [{ label: "candidate", fixture: issuer }] }) },
      governedIssuerProposals: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/issuer/${issuer.authorizationId}/proposal`;
      const post = (action: "prepare" | "submit" | "resolve", body: unknown) => fetch(`${endpoint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const notObserved = await post("resolve", { evidence });
      expect(notObserved.status).toBe(200);
      expect(notObserved.headers.get("cache-control")).toBe("no-store");
      expect(await notObserved.json()).toEqual({ state: "not-observed" });
      expect((await post("resolve", { evidence: { ...evidence, rawPresentation: "private" } })).status).toBe(400);
      expect((await post("prepare", {
        evidence: { ...evidence, rawPresentation: "private-presentation-payload" },
      })).status).toBe(400);
      expect((await post("prepare", {
        evidence: { ...evidence, envelope: { ...evidence.envelope, rawCredential: "private-vc" } },
      })).status).toBe(400);
      const preparedResponse = await post("prepare", { evidence });
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const prepared = await preparedResponse.json() as PreparedGovernedIssuerProposal;
      expect(prepared.evidenceHash).toBe(evidence.commitment);
      const verifierSignature = harness.signIssuerProposalEvidence(
        harness.prepareIssuerProposalAction(issuer, evidence),
      );
      const submit = (context: PreparedGovernedIssuerProposal, signers: ReturnType<typeof signPrepared>[]) =>
        post("submit", {
          evidence,
          prepared: context,
          signers,
          evidenceVerifierSignature: `0x${Buffer.from(encodeJubjubSignature(verifierSignature)).toString("hex")}`,
        });
      const first = signPrepared(harness, second, prepared);
      const other = signPrepared(harness, third, prepared);
      expect((await post("prepare", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(403);
      expect((await submit(prepared, [first])).status).toBe(403);
      const wrongVerifierSignature = signIssuerProposalEvidenceFromSeed(
        second.seed, bytes(prepared.registryId), bytes(prepared.evidenceVerifierKeyIdCommitment),
        bytes(prepared.actionPayloadHash),
      );
      expect((await post("submit", {
        evidence,
        prepared,
        signers: [first, other],
        evidenceVerifierSignature: `0x${Buffer.from(encodeJubjubSignature(wrongVerifierSignature)).toString("hex")}`,
      })).status).toBe(403);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        [first, other])).status).toBe(409);
      const accepted = await submit(prepared, [first, other]);
      expect(accepted.status).toBe(202);
      const receipt = await accepted.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(1n);
      expect((await submit(prepared, [first, other])).status).toBe(409);
      const recovered = await post("resolve", { evidence });
      expect(recovered.status).toBe(200);
      expect(await recovered.json()).toEqual({ state: "observed", eventHash: receipt.eventHash });
      expect((await post("resolve", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(409);
      delete port.resolve;
      expect((await post("resolve", { evidence })).status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
