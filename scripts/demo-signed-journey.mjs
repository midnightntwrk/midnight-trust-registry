import assert from "node:assert/strict";
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
  createTrustRegistryApiServer,
  createWorkspaceFileSource,
} from "../packages/trust-registry-api/dist/index.js";
import { TrustRegistryApplicantPortalClient } from "../packages/trust-registry-applicant-portal/dist/api.js";
import { TrustRegistryAdminConsoleClient } from "../packages/trust-registry-admin-console/dist/api.js";

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

const intentFor = (context, operation, actorDid, actorRole, nonceByte) => ({
  version: "tr-mutation-intent-v1",
  registryId: context.registryId,
  actorDid,
  actorKeyId: `${actorDid}#assertion-1`,
  actorRole,
  action: operation.operation,
  target: operation.operation === "publish-epoch" ? "epoch" : operation.target,
  targetId: operation.operation === "publish-epoch"
    ? context.expectedEpochId : fixture.authorizationId,
  scopeCommitment: operation.operation === "publish-epoch"
    ? computeAuthorizationScopeCommitment({
      version: "tr-scope-v1", role: "maintainer", registryId: context.registryId,
    })
    : computeAuthorizationScopeCommitment(fixture.authorizationScope),
  payloadCommitment: computeMutationPayloadCommitment(operationPayload(operation)),
  nonce: `0x${nonceByte.repeat(32)}`,
  expectedWorkspaceCommitment: context.expectedWorkspaceCommitment,
  expectedEpochId: context.expectedEpochId,
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
  const applicant = new TrustRegistryApplicantPortalClient(baseUrl);
  const admin = new TrustRegistryAdminConsoleClient(baseUrl);
  const post = (path, body) => fetch(`${baseUrl}${path}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const submit = { operation: "submit", target: "issuer", label: "signed-demo-issuer" };
  const applicantContext = await applicant.loadMutationContext();
  const applicantIntent = intentFor(applicantContext, submit, fixture.subjectDid, "applicant", "33");
  const applicantEnvelope = {
    intent: applicantIntent, signature: signatureFor(applicantIntent, applicantSeed), operation: submit,
  };

  await expectStatus(await post("/v1/applications", { target: "issuer", label: "unsigned" }), 403);
  await assert.rejects(applicant.submitSignedMutation({
    ...applicantEnvelope,
    signature: { ...applicantEnvelope.signature, value: `0x${"00".repeat(96)}` },
  }), (error) => error.problem?.status === 401);
  const operations = [];
  const submitted = await applicant.submitSignedMutation(applicantEnvelope);
  assert.equal(submitted.recordKind, "authorization");
  operations.push(submitted.operation.operation);
  await assert.rejects(applicant.submitSignedMutation(applicantEnvelope),
    (error) => error.problem?.status === 409);
  const staleIntent = intentFor(applicantContext, submit, fixture.subjectDid, "applicant", "37");
  await assert.rejects(applicant.submitSignedMutation({
    intent: staleIntent, signature: signatureFor(staleIntent, applicantSeed), operation: submit,
  }), (error) => error.problem?.status === 409 && /^stale-(epoch|workspace)$/u.test(error.problem?.detail));

  for (const [index, action] of ["approve", "activate"].entries()) {
    const context = await admin.loadMutationContext();
    const operation = { operation: action, target: "issuer", id: fixture.authorizationId };
    const intent = intentFor(context, operation, maintainerDid, "maintainer", index === 0 ? "34" : "35");
    const result = await admin.submitSignedMutation({
      intent, signature: signatureFor(intent, maintainerSeed), operation,
    });
    assert.equal(result.recordKind, "authorization");
    operations.push(result.operation.operation);
  }
  const invalidContext = await admin.loadMutationContext();
  const invalidApprove = { operation: "approve", target: "issuer", id: fixture.authorizationId };
  const invalidIntent = intentFor(invalidContext, invalidApprove, maintainerDid, "maintainer", "38");
  await assert.rejects(admin.submitSignedMutation({
    intent: invalidIntent, signature: signatureFor(invalidIntent, maintainerSeed), operation: invalidApprove,
  }), (error) => error.problem?.status === 403
    && error.problem?.type?.endsWith("/signed-operation-mismatch"));

  const beforeEpoch = await admin.loadMutationContext();
  const publish = { operation: "publish-epoch", label: "signed-demo-epoch" };
  const epochIntent = intentFor(beforeEpoch, publish, maintainerDid, "maintainer", "36");
  const published = await admin.submitSignedMutation({
    intent: epochIntent, signature: signatureFor(epochIntent, maintainerSeed), operation: publish,
  });
  assert.equal(published.recordKind, "epoch");
  operations.push(published.operation.operation);
  const current = await admin.loadMutationContext();
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
  const evaluatedAt = evidence.epoch.validFrom;
  const publicDecision = await expectStatus(await post("/v1/authorizations/evaluate", {
    role: "issuer", subjectDid: fixture.subjectDid, resourceId: fixture.resourceId, at: evaluatedAt,
  }), 200);
  const trqpRequest = {
    entity_id: fixture.subjectDid,
    authority_id: workspace.snapshot.registry.registryDid,
    action: "issue",
    resource: fixture.resourceId,
    context: { time: evaluatedAt },
  };
  const trqpDecision = await expectStatus(await post("/v1/trqp/authorizations/query", trqpRequest), 200);
  const trqpEvidence = await expectStatus(await post("/v1/trqp/authorizations/evidence", trqpRequest), 200);
  assert.equal(publicDecision.trustedAtTime, true);
  assert.equal(trqpDecision.authorized, publicDecision.trustedAtTime);
  assert.equal(trqpEvidence.authorized, publicDecision.trustedAtTime);
  assert.equal(trqpEvidence.bundle.epoch.stateRoot, evidence.epoch.stateRoot);
  assert.equal(trqpEvidence.bundle.inclusionProof.leafHash, evidence.inclusionProof.leafHash);

  process.stdout.write(`${JSON.stringify({
    mode: "local-simulator-fixture; finality simulated",
    registryId: current.registryId,
    applicantDid: fixture.subjectDid,
    authorizationId: fixture.authorizationId,
    scopeCommitment: computeAuthorizationScopeCommitment(fixture.authorizationScope),
    maintainerDid,
    status: entry.authorization.status,
    epochId: current.expectedEpochId,
    stateRoot: evidence.epoch.stateRoot,
    operations,
    publicAndTrqpAgree: trqpDecision.authorized === publicDecision.trustedAtTime,
    trqpEvidenceCommitment: trqpEvidence.bundle.inclusionProof.leafHash,
    expectedRejections: ["unsigned:403", "invalid-signature:401", "replay:409", "stale-context:409", "invalid-transition:403", "wrong-query-scope:404"],
  }, null, 2)}\n`);
} finally {
  if (server !== undefined) await new Promise((resolve) => server.close(resolve));
  await rm(temporaryDirectory, { recursive: true, force: true });
}
