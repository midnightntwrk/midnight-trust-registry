import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedMembershipActionRejectedError,
  type GovernedMembershipActionPort,
  type PreparedGovernedMembershipAction,
} from "../governed-membership-actions.js";
import { createTrustRegistryApiServer } from "../server.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (maintainer: MaintainerScenarioFixture, prepared: PreparedGovernedMembershipAction) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    bytes(prepared.registryId),
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

describe("Compact-backed membership governance over HTTP", () => {
  it("requires an injected port instead of replaying a workspace mutation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("governed-http-unavailable");
    const server = createTrustRegistryApiServer({
      source: {
        mode: "memory",
        loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "unavailable" }),
      },
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const response = await fetch(
        `http://127.0.0.1:${address.port}/v1/governed/issuer/missing/actions/approve`,
      );
      expect(response.status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("approves and activates one proposed issuer with 2-of-3 external signatures", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("governed-http");
    const second = createMaintainerScenarioFixture("governed-http-second");
    const third = createMaintainerScenarioFixture("governed-http-third");
    const issuer = createIssuerScenarioFixture("governed-http-issuer");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.proposeIssuer(issuer, [second]);

    const fixtures = { label: "governed-http", issuers: [{ label: "issuer", fixture: issuer }] };
    let snapshot = publishSimulatorSnapshot(harness, fixtures);
    const port: GovernedMembershipActionPort = {
      async prepare(role, authorizationId, action) {
        if (role !== "issuer" || authorizationId !== issuer.authorizationId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        return harness.prepareIssuerDecisionAction(issuer, action);
      },
      async execute(role, authorizationId, action, signers) {
        if (role !== "issuer" || authorizationId !== issuer.authorizationId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeIssuerDecisionWithSignatures(issuer, action, signers);
        } catch {
          throw new GovernedMembershipActionRejectedError("invalid-signers");
        }
        snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => snapshot },
      governedMembershipActions: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      const url = (action: "approve" | "activate") =>
        `${base}/v1/governed/issuer/${issuer.authorizationId}/actions/${action}`;
      const post = (action: "approve" | "activate", prepared: PreparedGovernedMembershipAction,
        signers: ReturnType<typeof signPrepared>[]) => fetch(url(action), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prepared, signers }),
      });

      const missing = await fetch(`${base}/v1/governed/issuer/unknown/actions/approve`);
      expect(missing.status).toBe(404);
      const preparedResponse = await fetch(url("approve"));
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const approval = await preparedResponse.json() as PreparedGovernedMembershipAction;
      const first = signPrepared(second, approval);
      const next = signPrepared(third, approval);
      const before = harness.simulator.getLedger().governanceActionCount;

      expect((await post("approve", approval, [first])).status).toBe(403);
      expect((await post("approve", approval, [first, first])).status).toBe(403);
      expect((await post("approve", approval, [
        { ...first, signature: "0x01" }, next,
      ])).status).toBe(400);
      expect((await post("approve", { ...approval, policyCommitment: `0x${"00".repeat(32)}` },
        [first, next])).status).toBe(409);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before);

      const approved = await post("approve", approval, [first, next]);
      expect(approved.status).toBe(202);
      expect(await approved.json()).toMatchObject({ eventHash: expect.stringMatching(/^0x[0-9a-f]{64}$/u) });
      expect((await post("approve", approval, [first, next])).status).toBe(409);
      const approvedRecord = await fetch(`${base}/v1/authorizations/issuer/${issuer.authorizationId}`);
      expect(approvedRecord.status).toBe(200);
      expect((await approvedRecord.json()).authorization.status).toBe("authorized");

      const activationResponse = await fetch(url("activate"));
      expect(activationResponse.status).toBe(200);
      const activation = await activationResponse.json() as PreparedGovernedMembershipAction;
      expect(activation.actionSequence).not.toBe(approval.actionSequence);
      expect((await post("activate", activation, [
        signPrepared(second, activation), signPrepared(third, activation),
      ])).status).toBe(202);

      const evidenceResponse = await fetch(
        `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
      );
      expect(evidenceResponse.status).toBe(200);
      const bundle = await evidenceResponse.json();
      expect(bundle.authorization.status).toBe("active");
      expect(() => new TrustRegistrySimulatorClient(harness.simulator)
        .verifyIssuerAuthorizationBundle(bundle, {})).not.toThrow();
      expect(snapshot.evidenceArchive.map((entry) => entry.authorization?.status))
        .toEqual(expect.arrayContaining(["proposed", "authorized"]));
      for (const archived of snapshot.evidenceArchive) {
        expect(snapshot.epochs).toContainEqual(archived.epoch);
      }

      const wrongScope = await fetch(`${base}/v1/authorizations/resolve`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          role: "issuer", subjectDid: issuer.subjectDid,
          resourceId: createIssuerScenarioFixture("another-resource").resourceId,
        }),
      });
      expect(wrongScope.status).toBe(404);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("archives a pending issuer through a fresh externally signed HTTP action", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("governed-http-denial");
    const second = createMaintainerScenarioFixture("denial-http-second");
    const third = createMaintainerScenarioFixture("denial-http-third");
    const issuer = createIssuerScenarioFixture("denial-http-issuer");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.proposeIssuer(issuer, [second]);
    const fixtures = { label: "governed-http-denial", issuers: [{ label: "issuer", fixture: issuer }] };
    let snapshot = publishSimulatorSnapshot(harness, fixtures);
    const port: GovernedMembershipActionPort = {
      async prepare(role, id, action) {
        if (role !== "issuer" || id !== issuer.authorizationId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        return harness.prepareIssuerDecisionAction(issuer, action);
      },
      async execute(role, id, action, signers) {
        if (role !== "issuer" || id !== issuer.authorizationId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeIssuerDecisionWithSignatures(issuer, action, signers);
        } catch {
          throw new GovernedMembershipActionRejectedError("invalid-signers");
        }
        snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => snapshot },
      governedMembershipActions: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      const url = `${base}/v1/governed/issuer/${issuer.authorizationId}/actions/archive`;
      const preparedResponse = await fetch(url);
      expect(preparedResponse.status).toBe(200);
      const prepared = await preparedResponse.json() as PreparedGovernedMembershipAction;
      const post = (body: unknown) => fetch(url, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const first = signPrepared(second, prepared);
      const thirdSigner = signPrepared(third, prepared);
      const before = harness.simulator.getLedger().governanceActionCount;
      expect((await post({ prepared, signers: [first] })).status).toBe(403);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
      expect((await post({ prepared: { ...prepared, actionKind: `0x${"00".repeat(32)}` },
        signers: [first, thirdSigner] })).status).toBe(409);
      const accepted = await post({ prepared, signers: [first, thirdSigner] });
      expect(accepted.status, await accepted.text()).toBe(202);
      expect((await post({ prepared, signers: [first, thirdSigner] })).status).toBe(409);
      const record = harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment);
      expect(record.status).toBe(AuthorizationStatus.archived);
      expect(record.archivedAtSequence).toBe(before);
      expect(snapshot.evidenceArchive.some((entry) => entry.authorization?.status === "proposed")).toBe(true);

      const active = await fetch(`${base}/v1/authorizations/issuer?status=active`);
      expect(active.status).toBe(200);
      expect((await active.json()).total).toBe(0);
      const archived = await fetch(`${base}/v1/authorizations/issuer?status=archived`);
      expect(archived.status).toBe(200);
      const archivedList = await archived.json();
      expect(archivedList.total).toBe(1);
      expect(archivedList.entries[0].authorization.authorizationId).toBe(issuer.authorizationId);
      expect(archivedList.entries[0].authorization.authorizedAt).toBeUndefined();
      expect(archivedList.entries[0].authorization.activeFrom).toBeUndefined();

      const evidenceResponse = await fetch(
        `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
      );
      expect(evidenceResponse.status).toBe(200);
      const bundle = await evidenceResponse.json();
      expect(bundle.authorization.status).toBe("archived");
      const client = new TrustRegistrySimulatorClient(harness.simulator);
      expect(() => client.verifyIssuerAuthorizationBundle(bundle, {})).toThrow(/not active/iu);
      expect(() => client.verifyIssuerAuthorizationBundle(bundle, { requireActive: false }))
        .not.toThrow();

      const scope = {
        role: "issuer",
        subjectDid: issuer.subjectDid,
        resourceId: issuer.resourceId,
      };
      const evaluation = await fetch(`${base}/v1/authorizations/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...scope, at: bundle.authorization.archivedAt }),
      });
      expect(evaluation.status).toBe(200);
      const decision = await evaluation.json();
      expect(decision.statusAtTime).toBe("archived");
      expect(decision.trustedAtTime).toBe(false);
      const proposedEvaluation = await fetch(`${base}/v1/authorizations/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...scope, at: bundle.authorization.proposedAt }),
      });
      expect(proposedEvaluation.status).toBe(200);
      const proposedDecision = await proposedEvaluation.json();
      expect(proposedDecision.statusAtTime).toBe("proposed");
      expect(proposedDecision.trustedAtTime).toBe(false);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("keeps verifier and auditor decision routes role-disjoint under one 2-of-3 policy", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("governed-request-roles");
    const second = createMaintainerScenarioFixture("request-role-second");
    const third = createMaintainerScenarioFixture("request-role-third");
    const verifier = createVerifierScenarioFixture("request-role-verifier");
    const auditor = createAuditorScenarioFixture("request-role-auditor");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.proposeVerifier(verifier);
    harness.proposeAuditor(auditor);
    const fixtures = {
      label: "governed-request-roles",
      verifiers: [{ label: "verifier", fixture: verifier }],
      auditors: [{ label: "auditor", fixture: auditor }],
    };
    let snapshot = publishSimulatorSnapshot(harness, fixtures);
    const port: GovernedMembershipActionPort = {
      async prepare(role, authorizationId, action) {
        if (role === "verifier" && authorizationId === verifier.authorizationId) {
          return harness.prepareVerifierDecisionAction(verifier, action);
        }
        if (role === "auditor" && authorizationId === auditor.authorizationId) {
          return harness.prepareAuditorDecisionAction(auditor, action);
        }
        throw new GovernedMembershipActionRejectedError("unknown-authorization");
      },
      async execute(role, authorizationId, action, signers) {
        let eventHash: Uint8Array;
        try {
          if (role === "verifier" && authorizationId === verifier.authorizationId) {
            eventHash = harness.executeVerifierDecisionWithSignatures(verifier, action, signers);
          } else if (role === "auditor" && authorizationId === auditor.authorizationId) {
            eventHash = harness.executeAuditorDecisionWithSignatures(auditor, action, signers);
          } else {
            throw new GovernedMembershipActionRejectedError("unknown-authorization");
          }
        } catch (error) {
          if (error instanceof GovernedMembershipActionRejectedError) throw error;
          throw new GovernedMembershipActionRejectedError("invalid-signers");
        }
        snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => snapshot },
      governedMembershipActions: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      expect((await fetch(`${base}/v1/governed/auditor/${verifier.authorizationId}/actions/approve`)).status)
        .toBe(404);
      expect((await fetch(`${base}/v1/governed/verifier/${auditor.authorizationId}/actions/approve`)).status)
        .toBe(404);
      expect((await fetch(`${base}/v1/governed/maintainer/${verifier.authorizationId}/actions/approve`)).status)
        .toBe(404);

      for (const [role, fixture] of [["verifier", verifier], ["auditor", auditor]] as const) {
        for (const action of ["approve", "activate"] as const) {
          const endpoint = `${base}/v1/governed/${role}/${fixture.authorizationId}/actions/${action}`;
          const preparedResponse = await fetch(endpoint);
          expect(preparedResponse.status).toBe(200);
          const prepared = await preparedResponse.json() as PreparedGovernedMembershipAction;
          const before = harness.simulator.getLedger().governanceActionCount;
          const insufficient = await fetch(endpoint, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ prepared, signers: [signPrepared(second, prepared)] }),
          });
          expect(insufficient.status).toBe(403);
          expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
          const accepted = await fetch(endpoint, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              prepared,
              signers: [signPrepared(second, prepared), signPrepared(third, prepared)],
            }),
          });
          expect(accepted.status).toBe(202);
        }
        const evidence = await fetch(
          `${base}/v1/authorizations/${role}/${fixture.authorizationId}/evidence`,
        );
        expect(evidence.status).toBe(200);
        const bundle = await evidence.json();
        expect(bundle.authorization.role).toBe(role);
        expect(bundle.authorization.status).toBe("active");
        const client = new TrustRegistrySimulatorClient(harness.simulator);
        if (role === "verifier") {
          expect(() => client.verifyVerifierAuthorizationBundle(bundle, {})).not.toThrow();
        } else {
          expect(() => client.verifyAuditorAuthorizationBundle(bundle, {})).not.toThrow();
        }
      }
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("requires existing-maintainer quorum for maintainer decisions over HTTP", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("governed-maintainer-http");
    const second = createMaintainerScenarioFixture("governed-maintainer-second");
    const third = createMaintainerScenarioFixture("governed-maintainer-third");
    const candidate = createMaintainerScenarioFixture("governed-maintainer-candidate");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: candidate.maintainerId,
      subjectDid: candidate.subjectDid,
      role: "maintainer",
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    });
    harness.proposeMaintainerWithApplicationEvidence(candidate, evidence);

    const port: GovernedMembershipActionPort = {
      async prepare(role, authorizationId, action) {
        if (role !== "maintainer" || authorizationId !== candidate.maintainerId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        const prepared = harness.prepareMaintainerDecisionAction(candidate, action);
        if (prepared.previousLifecycleEventHash === undefined) throw new Error("Missing lifecycle event");
        return {
          ...prepared,
          previousLifecycleEventHash: prepared.previousLifecycleEventHash,
        };
      },
      async execute(role, authorizationId, action, signers) {
        if (role !== "maintainer" || authorizationId !== candidate.maintainerId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeMaintainerDecisionWithSignatures(candidate, action, signers);
        } catch {
          throw new GovernedMembershipActionRejectedError("invalid-signers");
        }
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const server = createTrustRegistryApiServer({
      source: {
        mode: "memory",
        loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "governed-maintainer-http" }),
      },
      governedMembershipActions: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      const endpoint = (action: "approve" | "activate") =>
        `${base}/v1/governed/maintainer/${candidate.maintainerId}/actions/${action}`;
      const post = (action: "approve" | "activate", prepared: PreparedGovernedMembershipAction,
        signers: ReturnType<typeof signPrepared>[]) => fetch(endpoint(action), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prepared, signers }),
      });

      expect((await fetch(`${base}/v1/governed/issuer/${candidate.maintainerId}/actions/approve`)).status)
        .toBe(404);
      expect((await fetch(`${base}/v1/governed/maintainer/unknown/actions/approve`)).status)
        .toBe(404);
      for (const action of ["approve", "activate"] as const) {
        const preparedResponse = await fetch(endpoint(action));
        expect(preparedResponse.status).toBe(200);
        expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
        const prepared = await preparedResponse.json() as PreparedGovernedMembershipAction;
        expect(prepared.targetId).toBe(`0x${Buffer.from(candidate.maintainerIdCommitment).toString("hex")}`);
        const before = harness.simulator.getLedger().governanceActionCount;
        expect((await post(action, prepared, [signPrepared(second, prepared)])).status).toBe(403);
        expect((await post(action, prepared, [
          signPrepared(second, prepared), signPrepared(candidate, prepared),
        ])).status).toBe(403);
        expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
        expect((await post(action, prepared, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ])).status).toBe(202);
        expect((await post(action, prepared, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ])).status).toBe(409);
      }
      expect(harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status)
        .toBe(AuthorizationStatus.active);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("governs external recognition without granting local membership", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("governed-recognition-http");
    const second = createMaintainerScenarioFixture("governed-recognition-second");
    const third = createMaintainerScenarioFixture("governed-recognition-third");
    const recognition = createRecognitionScenarioFixture("governed-recognition-authority");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.proposeRecognition(recognition);

    const fixtures = { label: "governed-recognition-http", recognitions: [{ label: "authority", fixture: recognition }] };
    let snapshot = publishSimulatorSnapshot(harness, fixtures);
    const port: GovernedMembershipActionPort = {
      async prepare(role, authorizationId, action) {
        if (role !== "recognition" || authorizationId !== recognition.recognitionId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        const prepared = harness.prepareRecognitionDecisionAction(recognition, action);
        if (prepared.previousLifecycleEventHash === undefined) throw new Error("Missing lifecycle event");
        return {
          ...prepared,
          previousLifecycleEventHash: prepared.previousLifecycleEventHash,
        };
      },
      async execute(role, authorizationId, action, signers) {
        if (role !== "recognition" || authorizationId !== recognition.recognitionId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeRecognitionDecisionWithSignatures(recognition, action, signers);
        } catch {
          throw new GovernedMembershipActionRejectedError("invalid-signers");
        }
        snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => snapshot },
      governedMembershipActions: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      const endpoint = (action: "approve" | "activate") =>
        `${base}/v1/governed/recognition/${recognition.recognitionId}/actions/${action}`;
      const post = (action: "approve" | "activate", prepared: PreparedGovernedMembershipAction,
        signers: ReturnType<typeof signPrepared>[]) => fetch(endpoint(action), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prepared, signers }),
      });

      expect((await fetch(`${base}/v1/governed/issuer/${recognition.recognitionId}/actions/approve`)).status)
        .toBe(404);
      for (const action of ["approve", "activate"] as const) {
        const response = await fetch(endpoint(action));
        expect(response.status).toBe(200);
        expect(response.headers.get("cache-control")).toBe("no-store");
        const prepared = await response.json() as PreparedGovernedMembershipAction;
        expect(prepared.targetId).toBe(`0x${Buffer.from(recognition.recognitionIdCommitment).toString("hex")}`);
        const before = harness.simulator.getLedger().governanceActionCount;
        expect((await post(action, prepared, [signPrepared(second, prepared)])).status).toBe(403);
        expect((await post(action, { ...prepared, policyCommitment: `0x${"00".repeat(32)}` }, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ])).status).toBe(409);
        expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
        expect((await post(action, prepared, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ])).status).toBe(202);
        expect((await post(action, prepared, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ])).status).toBe(409);
      }
      const evidenceResponse = await fetch(`${base}/v1/recognitions/${recognition.recognitionId}/evidence`);
      expect(evidenceResponse.status).toBe(200);
      const bundle = await evidenceResponse.json();
      expect(bundle.recognition.status).toBe("active");
      expect(bundle.recognition.recognizedRegistryId).toBe(recognition.recognizedRegistryId);
      expect(bundle.authorization).toBeUndefined();
      expect(() => new TrustRegistrySimulatorClient(harness.simulator)
        .verifyRecognitionBundle(bundle, {})).not.toThrow();
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("keeps a denied recognition queryable without treating it as local membership", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("governed-recognition-denial-http");
    const second = createMaintainerScenarioFixture("recognition-denial-second");
    const third = createMaintainerScenarioFixture("recognition-denial-third");
    const recognition = createRecognitionScenarioFixture("denied-external-authority");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.proposeRecognition(recognition);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const fixtures = {
      label: "governed-recognition-denial-http",
      recognitions: [{ label: "denied-authority", fixture: recognition }],
    };
    let snapshot = publishSimulatorSnapshot(harness, fixtures);
    const port: GovernedMembershipActionPort = {
      async prepare(role, id, action) {
        if (role !== "recognition" || id !== recognition.recognitionId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        const prepared = harness.prepareRecognitionDecisionAction(recognition, action);
        if (prepared.previousLifecycleEventHash === undefined) throw new Error("Missing lifecycle event");
        return { ...prepared, previousLifecycleEventHash: prepared.previousLifecycleEventHash };
      },
      async execute(role, id, action, signers) {
        if (role !== "recognition" || id !== recognition.recognitionId) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeRecognitionDecisionWithSignatures(recognition, action, signers);
        } catch {
          throw new GovernedMembershipActionRejectedError("invalid-signers");
        }
        snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => snapshot },
      governedMembershipActions: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      const endpoint = `${base}/v1/governed/recognition/${recognition.recognitionId}/actions/archive`;
      const contextResponse = await fetch(endpoint);
      expect(contextResponse.status).toBe(200);
      const prepared = await contextResponse.json() as PreparedGovernedMembershipAction;
      const post = (signers: ReturnType<typeof signPrepared>[]) => fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prepared, signers }),
      });
      const signers = [signPrepared(second, prepared), signPrepared(third, prepared)];
      expect((await post(signers.slice(0, 1))).status).toBe(403);
      expect((await post(signers)).status).toBe(202);
      expect((await post(signers)).status).toBe(409);

      const evidenceResponse = await fetch(`${base}/v1/recognitions/${recognition.recognitionId}/evidence`);
      expect(evidenceResponse.status).toBe(200);
      const bundle = await evidenceResponse.json();
      expect(bundle.recognition.status).toBe("archived");
      expect(bundle.recognition.authorizedAt).toBeUndefined();
      expect(bundle.recognition.effectiveFrom).toBeUndefined();
      expect(bundle.authorization).toBeUndefined();
      const client = new TrustRegistrySimulatorClient(harness.simulator);
      expect(() => client.verifyRecognitionBundle(bundle, {})).toThrow(/not active/iu);
      expect(() => client.verifyRecognitionBundle(bundle, { requireActive: false })).not.toThrow();

      const evaluation = await fetch(`${base}/v1/recognitions/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          recognizedAuthorityDid: recognition.recognizedAuthorityDid,
          recognizedRegistryId: recognition.recognizedRegistryId,
          scopeResourceType: recognition.scopeResourceType,
          scopeResourceId: recognition.scopeResourceId,
          at: bundle.recognition.archivedAt,
        }),
      });
      expect(evaluation.status).toBe(200);
      const decision = await evaluation.json();
      expect(decision.statusAtTime).toBe("archived");
      expect(decision.trustedAtTime).toBe(false);

      const localMembership = await fetch(`${base}/v1/authorizations/issuer?status=active`);
      expect(localMembership.status).toBe(200);
      expect((await localMembership.json()).total).toBe(0);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
