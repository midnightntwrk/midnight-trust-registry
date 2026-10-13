import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createTrustRegistryApiServer,
  GovernedIssuerActionRejectedError,
} from "../packages/trust-registry-api/dist/index.js";

const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");
const sign = (maintainer, prepared) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    fromHex(prepared.registryId),
    fromHex(prepared.policyCommitment),
    fromHex(prepared.actionKind),
    fromHex(prepared.actionPayloadHash),
    BigInt(prepared.actionSequence),
  );
  return {
    keyId: asHex(maintainer.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: asHex(encodeJubjubSignature(signature)),
  };
};

const expectHttp = async (response, status) => {
  const payload = await response.json();
  assert.equal(response.status, status, JSON.stringify(payload));
  return payload;
};

const harness = new LocalTrustRegistryIntegrationHarness("governed-issuer-demo");
const second = createMaintainerScenarioFixture("governed-demo-second");
const third = createMaintainerScenarioFixture("governed-demo-third");
const issuer = createIssuerScenarioFixture("governed-demo-issuer");
harness.authorizeMaintainer(second);
harness.authorizeMaintainer(third);
harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
harness.proposeIssuer(issuer, [second]);

const fixtures = { label: "governed-issuer-demo", issuers: [{ label: "issuer", fixture: issuer }] };
let snapshot = publishSimulatorSnapshot(harness, fixtures);
const server = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => snapshot },
  governedIssuerActions: {
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
      let eventHash;
      try {
        eventHash = harness.executeIssuerDecisionWithSignatures(issuer, action, signers);
      } catch {
        throw new GovernedIssuerActionRejectedError("invalid-signers");
      }
      snapshot = publishSimulatorSnapshot(harness, fixtures);
      return { eventHash: asHex(eventHash) };
    },
  },
});

try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const base = `http://127.0.0.1:${address.port}`;
  const actionUrl = (action) =>
    `${base}/v1/governed/issuers/${issuer.authorizationId}/actions/${action}`;
  const submit = (action, prepared, signers) => fetch(actionUrl(action), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ prepared, signers }),
  });

  const approval = await expectHttp(await fetch(actionUrl("approve")), 200);
  const approvalSigners = [sign(second, approval), sign(third, approval)];
  await expectHttp(await submit("approve", approval, approvalSigners.slice(0, 1)), 403);
  const approved = await expectHttp(await submit("approve", approval, approvalSigners), 202);
  await expectHttp(await submit("approve", approval, approvalSigners), 409);

  const activation = await expectHttp(await fetch(actionUrl("activate")), 200);
  const activated = await expectHttp(await submit("activate", activation, [
    sign(second, activation), sign(third, activation),
  ]), 202);
  const bundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(bundle.authorization.status, "active");
  new TrustRegistrySimulatorClient(harness.simulator).verifyIssuerAuthorizationBundle(bundle, {});
  await expectHttp(await fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      role: "issuer",
      subjectDid: issuer.subjectDid,
      resourceId: createIssuerScenarioFixture("wrong-scope").resourceId,
    }),
  }), 404);

  process.stdout.write(`${JSON.stringify({
    mode: "Compact simulator fixture; not network finality",
    registryId: harness.registryId,
    issuerDid: issuer.subjectDid,
    authorizationId: issuer.authorizationId,
    scopeResourceId: issuer.resourceId,
    governance: "2-of-3 external JubJub signatures",
    approvalEventHash: approved.eventHash,
    activationEventHash: activated.eventHash,
    status: bundle.authorization.status,
    stateRoot: bundle.epoch.stateRoot,
    evidence: "independently verified against the same simulator",
    expectedRejections: ["one-signer:403", "replayed-context:409", "wrong-scope:404"],
  }, null, 2)}\n`);
} finally {
  await new Promise((resolve) => server.close(resolve));
}
