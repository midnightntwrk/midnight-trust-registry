import { Buffer } from "node:buffer";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import {
  createOperatorWorkspace,
  loadWorkspaceFromFile,
  writeWorkspaceToFile,
} from "../packages/trust-registry-cli/dist/index.js";
import {
  computeAuthorizationScopeCommitment,
  computeMutationPayloadCommitment,
  mutationIntentDigestBytes,
} from "../packages/trust-registry-domain/dist/index.js";
import {
  createIssuerScenarioFixture,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  computeOperatorWorkspaceCommitment,
  createTrustRegistryApiServer,
  createWorkspaceFileSource,
} from "../packages/trust-registry-api/dist/index.js";

const fixture = createIssuerScenarioFixture("signed-demo-issuer");
const applicantSeed = new Uint8Array(32).fill(47);
const maintainerSeed = new Uint8Array(32).fill(61);
const now = "2026-10-10T00:01:00.000Z";

const signatureFor = (intent, seed) => ({
  keyId: intent.actorKeyId,
  algorithm: "jubjub-schnorr",
  value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
    seed, mutationIntentDigestBytes(intent),
  ))).toString("hex")}`,
});

const operationPayload = (operation) => {
  if (operation.operation === "publish-epoch") {
    return operation.label === undefined ? {} : { label: operation.label };
  }
  return operation.operation === "submit"
    ? { target: operation.target, label: operation.label }
    : { target: operation.target, id: operation.id };
};

const intentFor = (workspace, operation, actorDid, actorRole, nonceByte) => ({
  version: "tr-mutation-intent-v1",
  registryId: workspace.snapshot.registry.registryId,
  actorDid,
  actorKeyId: `${actorDid}#assertion-1`,
  actorRole,
  action: operation.operation,
  target: operation.operation === "publish-epoch" ? "epoch" : operation.target,
  targetId: operation.operation === "publish-epoch"
    ? workspace.snapshot.currentEpoch.epochId : fixture.authorizationId,
  scopeCommitment: operation.operation === "publish-epoch"
    ? computeAuthorizationScopeCommitment({
      version: "tr-scope-v1", role: "maintainer", registryId: workspace.snapshot.registry.registryId,
    })
    : computeAuthorizationScopeCommitment(fixture.authorizationScope),
  payloadCommitment: computeMutationPayloadCommitment(operationPayload(operation)),
  nonce: `0x${nonceByte.repeat(32)}`,
  expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
  expectedEpochId: workspace.snapshot.currentEpoch.epochId,
  issuedAt: "2026-10-10T00:00:00.000Z",
  expiresAt: "2026-10-10T00:05:00.000Z",
});

const expectStatus = async (response, expected) => {
  const payload = await response.json();
  if (response.status !== expected) {
    throw new Error(`expected HTTP ${expected}, received ${response.status}: ${JSON.stringify(payload)}`);
  }
  return payload;
};

const temporaryDirectory = await mkdtemp(join(tmpdir(), "trust-registry-signed-demo-"));
const workspacePath = join(temporaryDirectory, "workspace.json");
let server;
try {
  const workspace = createOperatorWorkspace({ label: "signed-demo" });
  const maintainerDid = workspace.snapshot.registry.maintainerDids[0];
  if (maintainerDid === undefined) throw new Error("fixture maintainer missing");
  await writeWorkspaceToFile(workspacePath, workspace);
  const resolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(fixture.subjectDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
    }),
    createMidnightDidLedgerFixture(maintainerDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed),
      capabilityInvocation: true,
    }),
  ]);
  server = createTrustRegistryApiServer({
    source: createWorkspaceFileSource(workspacePath),
    mutationDidResolver: resolver,
    clock: () => now,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address missing");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const post = (path, body) => fetch(`${baseUrl}${path}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const submit = { operation: "submit", target: "issuer", label: "signed-demo-issuer" };
  const applicantIntent = intentFor(workspace, submit, fixture.subjectDid, "applicant", "33");
  const applicantEnvelope = {
    intent: applicantIntent, signature: signatureFor(applicantIntent, applicantSeed), operation: submit,
  };

  await expectStatus(await post("/v1/applications", { target: "issuer", label: "unsigned" }), 403);
  await expectStatus(await post("/v1/mutations", {
    ...applicantEnvelope,
    signature: { ...applicantEnvelope.signature, value: `0x${"00".repeat(96)}` },
  }), 401);
  await expectStatus(await post("/v1/mutations", applicantEnvelope), 201);
  await expectStatus(await post("/v1/mutations", applicantEnvelope), 409);

  for (const [index, action] of ["approve", "activate"].entries()) {
    const current = await loadWorkspaceFromFile(workspacePath);
    const operation = { operation: action, target: "issuer", id: fixture.authorizationId };
    const intent = intentFor(current, operation, maintainerDid, "maintainer", index === 0 ? "34" : "35");
    await expectStatus(await post("/v1/mutations", {
      intent, signature: signatureFor(intent, maintainerSeed), operation,
    }), 200);
  }

  const beforeEpoch = await loadWorkspaceFromFile(workspacePath);
  const publish = { operation: "publish-epoch", label: "signed-demo-epoch" };
  const epochIntent = intentFor(beforeEpoch, publish, maintainerDid, "maintainer", "36");
  await expectStatus(await post("/v1/mutations", {
    intent: epochIntent, signature: signatureFor(epochIntent, maintainerSeed), operation: publish,
  }), 200);
  const current = await loadWorkspaceFromFile(workspacePath);
  const entry = await expectStatus(await fetch(`${baseUrl}/v1/authorizations/issuer/${fixture.authorizationId}`), 200);
  const evidence = await expectStatus(await fetch(`${baseUrl}/v1/authorizations/issuer/${fixture.authorizationId}/evidence`), 200);
  const wrongScope = await post("/v1/authorizations/resolve", {
    role: "issuer", subjectDid: fixture.subjectDid,
    resourceId: createIssuerScenarioFixture("other-scope").resourceId,
  });
  await expectStatus(wrongScope, 404);
  if (entry.authorization.status !== "active" || evidence.authorization?.authorizationId !== fixture.authorizationId) {
    throw new Error("signed demo did not produce matching active issuer evidence");
  }

  process.stdout.write(`${JSON.stringify({
    mode: "local-simulator-fixture; finality simulated",
    registryId: current.snapshot.registry.registryId,
    applicantDid: fixture.subjectDid,
    authorizationId: fixture.authorizationId,
    scopeCommitment: computeAuthorizationScopeCommitment(fixture.authorizationScope),
    maintainerDid,
    status: entry.authorization.status,
    epochId: current.snapshot.currentEpoch.epochId,
    stateRoot: evidence.epoch.stateRoot,
    operations: current.operations.map((operation) => operation.operation),
    expectedRejections: ["unsigned:403", "invalid-signature:401", "replay:409", "wrong-query-scope:404"],
  }, null, 2)}\n`);
} finally {
  if (server !== undefined) await new Promise((resolve) => server.close(resolve));
  await rm(temporaryDirectory, { recursive: true, force: true });
}
