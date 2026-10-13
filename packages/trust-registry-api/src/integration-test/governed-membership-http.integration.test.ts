import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
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
        snapshot = publishSimulatorSnapshot(harness, fixtures);
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
        snapshot = publishSimulatorSnapshot(harness, fixtures);
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
        .toBe(400);

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
});
