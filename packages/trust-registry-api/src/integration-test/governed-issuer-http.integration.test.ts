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
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedIssuerActionRejectedError,
  type GovernedIssuerActionPort,
  type PreparedGovernedIssuerAction,
} from "../governed-issuer-actions.js";
import { createTrustRegistryApiServer } from "../server.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (maintainer: MaintainerScenarioFixture, prepared: PreparedGovernedIssuerAction) => {
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

describe("Compact-backed issuer governance over HTTP", () => {
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
        `http://127.0.0.1:${address.port}/v1/governed/issuers/missing/actions/approve`,
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
    const port: GovernedIssuerActionPort = {
      async prepare(authorizationId, action) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerActionRejectedError("unknown-authorization");
        }
        return harness.prepareIssuerDecisionAction(issuer, action);
      },
      async execute(authorizationId, action, signers) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerActionRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeIssuerDecisionWithSignatures(issuer, action, signers);
        } catch {
          throw new GovernedIssuerActionRejectedError("invalid-signers");
        }
        snapshot = publishSimulatorSnapshot(harness, fixtures);
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => snapshot },
      governedIssuerActions: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      const url = (action: "approve" | "activate") =>
        `${base}/v1/governed/issuers/${issuer.authorizationId}/actions/${action}`;
      const post = (action: "approve" | "activate", prepared: PreparedGovernedIssuerAction,
        signers: ReturnType<typeof signPrepared>[]) => fetch(url(action), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prepared, signers }),
      });

      const missing = await fetch(`${base}/v1/governed/issuers/unknown/actions/approve`);
      expect(missing.status).toBe(404);
      const preparedResponse = await fetch(url("approve"));
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const approval = await preparedResponse.json() as PreparedGovernedIssuerAction;
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
      const activation = await activationResponse.json() as PreparedGovernedIssuerAction;
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
});
