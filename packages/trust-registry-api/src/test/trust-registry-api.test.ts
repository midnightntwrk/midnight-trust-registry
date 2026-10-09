import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  applyWorkspaceOperation,
  collectDistinctEpochs,
  createDemoSnapshot,
  createOperatorWorkspace,
  resolveWorkspaceOperationRecord,
  writeSnapshotToFile,
  writeWorkspaceToFile,
  TrustRegistryOperatorSnapshotSchema,
  type TrustRegistryAuthorizationSnapshotEntry,
  type TrustRegistryRecognitionSnapshotEntry,
  type TrustRegistryOperatorWorkspace,
} from "@midnight-ntwrk/trust-registry-cli";
import { requestGovernedResourceId } from "@midnight-ntwrk/trust-registry-domain";
import {
  LocalTrustRegistryIntegrationHarness,
  bytes32Commitment,
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  createInMemorySource,
  createSnapshotFileSource,
  createTrqpSourceFromStateSource,
  createWorkspaceFileSource,
} from "../source.js";
import { createTrustRegistryApiServer } from "../server.js";

type ServerHarness = {
  close: () => Promise<void>;
  url: string;
};

const applyOperation = (
  workspace: TrustRegistryOperatorWorkspace,
  operation:
    Parameters<typeof applyWorkspaceOperation>[1],
): {
  nextWorkspace: TrustRegistryOperatorWorkspace;
  record:
    | TrustRegistryAuthorizationSnapshotEntry
    | TrustRegistryRecognitionSnapshotEntry
    | TrustRegistryOperatorWorkspace["snapshot"]["currentEpoch"];
} => {
  const nextWorkspace = applyWorkspaceOperation(workspace, operation);
  return {
    nextWorkspace,
    record: resolveWorkspaceOperationRecord(nextWorkspace, operation),
  };
};

const asAuthorizationRecord = (
  record:
    | TrustRegistryAuthorizationSnapshotEntry
    | TrustRegistryRecognitionSnapshotEntry
    | TrustRegistryOperatorWorkspace["snapshot"]["currentEpoch"],
): TrustRegistryAuthorizationSnapshotEntry => {
  if ("authorization" in record) {
    return record;
  }
  throw new Error("expected authorization workspace record");
};

const asRecognitionRecord = (
  record:
    | TrustRegistryAuthorizationSnapshotEntry
    | TrustRegistryRecognitionSnapshotEntry
    | TrustRegistryOperatorWorkspace["snapshot"]["currentEpoch"],
): TrustRegistryRecognitionSnapshotEntry => {
  if ("recognition" in record) {
    return record;
  }
  throw new Error("expected recognition workspace record");
};

const startServer = async (
  source: Parameters<typeof createTrustRegistryApiServer>[0]["source"],
): Promise<ServerHarness> => {
  const server = createTrustRegistryApiServer({ source });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("expected a TCP server address");
  }

  return {
    url: `http://127.0.0.1:${address.port.toString()}`,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error !== undefined) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    },
  };
};

describe("trust registry api", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "trust-registry-api-"));
  });

  afterEach(async () => {
    await rm(tempDir, { force: true, recursive: true });
  });

  it("keeps auditor current and historical lookups role-disjoint and scope-bound", async () => {
    const snapshot = createDemoSnapshot({ label: "auditor-query" });
    const [active, archived] = snapshot.auditorEntries;
    if (active === undefined || archived === undefined) {
      throw new Error("expected active and archived auditor fixtures");
    }
    const server = await startServer(createInMemorySource(snapshot));
    const lookup = (role: string, resourceId: string, at?: string) => fetch(
      `${server.url}/v1/authorizations/${at === undefined ? "resolve" : "evaluate"}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          role,
          subjectDid: active.authorization.subjectDid,
          resourceId,
          ...(at === undefined ? {} : { at }),
        }),
      },
    );
    try {
      const summary = await (await fetch(`${server.url}/v1/registry/summary`)).json();
      expect(summary.auditorCounts.active).toBe(1);
      expect(summary.auditorCounts.archived).toBe(1);

      const activeList = await fetch(`${server.url}/v1/authorizations/auditor?status=active`);
      expect(activeList.status).toBe(200);
      expect((await activeList.json()).entries[0].authorization.authorizationId).toBe(
        active.authorization.authorizationId,
      );
      const archivedList = await fetch(`${server.url}/v1/authorizations/auditor?status=archived`);
      expect(archivedList.status).toBe(200);
      expect((await archivedList.json()).entries[0].authorization.authorizationId).toBe(
        archived.authorization.authorizationId,
      );

      const resolved = await lookup("auditor", active.authorization.resourceId);
      expect(resolved.status).toBe(200);
      expect((await resolved.json()).authorization.authorizationId).toBe(active.authorization.authorizationId);
      const current = await lookup("auditor", active.authorization.resourceId, active.authorization.activeFrom);
      expect(current.status).toBe(200);
      expect((await current.json()).trustedAtTime).toBe(true);
      const historical = await fetch(`${server.url}/v1/authorizations/auditor/${archived.authorization.authorizationId}/evidence`);
      expect(historical.status).toBe(200);
      expect((await historical.json()).authorization.status).toBe("archived");

      expect((await lookup("verifier", active.authorization.resourceId)).status).toBe(404);
      expect((await lookup("auditor", "request-profile:compliance")).status).toBe(400);
    } finally {
      await server.close();
    }
  });

  it("returns a conflict rather than an internal error for duplicate auditor submissions", async () => {
    const workspacePath = join(tempDir, "auditor-workspace.json");
    await writeWorkspaceToFile(workspacePath, createOperatorWorkspace({ label: "auditor-duplicate" }));
    const server = await startServer(createWorkspaceFileSource(workspacePath));
    const submit = () => fetch(`${server.url}/v1/applications`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target: "auditor", label: "compliance" }),
    });
    try {
      expect((await submit()).status).toBe(201);
      const duplicate = await submit();
      expect(duplicate.status).toBe(409);
      expect((await duplicate.json()).type).toMatch(/duplicate-application$/);
    } finally {
      await server.close();
    }
  });

  it("does not collapse same-profile auditor grants with different purposes", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("auditor-scope-query");
    const first = createAuditorScenarioFixture("same-profile");
    const secondAuthorizationId = "auth:auditor:same-profile:other-purpose:v1";
    const secondPurpose = "financial-compliance";
    const secondResourceId = requestGovernedResourceId({
      ...createAuditorAuthorizationScopeFixture(first),
      purpose: secondPurpose,
    });
    const second = {
      ...first,
      authorizationId: secondAuthorizationId,
      authorizationIdCommitment: bytes32Commitment(secondAuthorizationId),
      purpose: secondPurpose,
      scopeResourceId: secondResourceId,
      requestResourceIdCommitment: bytes32Commitment(secondResourceId),
    };
    expect(second.subjectDid).toBe(first.subjectDid);
    expect(second.requestProfileId).toBe(first.requestProfileId);
    expect(second.scopeResourceId).not.toBe(first.scopeResourceId);

    harness.authorizeAuditor(first);
    harness.authorizeAuditor(second);
    harness.suspendAuditor(second);
    harness.revokeAuditor(second);
    harness.archiveAuditor(second);
    const activeEvidence = harness.evaluateCurrentAuditorDecision(first);
    const historicalEvidence = harness.buildAuditorHistoricalEvidence(second);
    const currentEpoch = harness.publishRegistryEpoch("auditor-query-current");
    const epochs = collectDistinctEpochs([activeEvidence, historicalEvidence]);
    if (!epochs.some((epoch) => epoch.epochId === currentEpoch.epochId)) {
      epochs.push(currentEpoch);
    }
    const snapshot = TrustRegistryOperatorSnapshotSchema.parse({
      snapshotVersion: "1",
      generatedAt: currentEpoch.validUntil,
      registryLabel: "auditor-scope-query",
      registry: harness.registryRecord,
      policy: harness.policyRecord,
      currentEpoch,
      epochs,
      issuerEntries: [],
      verifierEntries: [],
      auditorEntries: [
        { label: "first", authorization: activeEvidence.authorization, evidence: activeEvidence },
        { label: "second", authorization: historicalEvidence.authorization, evidence: historicalEvidence },
      ],
      recognitionEntries: [],
      notes: [],
    });
    const server = await startServer(createInMemorySource(snapshot));
    const lookup = (resourceId: string, at?: string) => fetch(
      `${server.url}/v1/authorizations/${at === undefined ? "resolve" : "evaluate"}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          role: "auditor",
          subjectDid: first.subjectDid,
          resourceId,
          ...(at === undefined ? {} : { at }),
        }),
      },
    );
    try {
      const firstResult = await lookup(first.scopeResourceId);
      const secondResult = await lookup(second.scopeResourceId);
      expect(firstResult.status).toBe(200);
      expect(secondResult.status).toBe(200);
      expect((await firstResult.json()).authorization.authorizationId).toBe(first.authorizationId);
      expect((await secondResult.json()).authorization.authorizationId).toBe(second.authorizationId);
      expect((await lookup(first.requestProfileId)).status).toBe(400);
      const historical = await lookup(second.scopeResourceId, historicalEvidence.authorization?.activeFrom);
      expect(historical.status).toBe(200);
      expect((await historical.json()).trustedAtTime).toBe(true);
      const noCurrentTrust = await lookup(second.scopeResourceId, historicalEvidence.authorization?.archivedAt);
      expect(noCurrentTrust.status).toBe(200);
      expect((await noCurrentTrust.json()).trustedAtTime).toBe(false);
    } finally {
      await server.close();
    }
  });

  it("serves registry summary, scoped authorization resolution, and evidence from a workspace file", async () => {
    let workspace = createOperatorWorkspace({ label: "kanon-api" });

    const issuerSubmit = applyOperation(workspace, {
      operation: "submit",
      target: "issuer",
      label: "degree",
    });
    workspace = issuerSubmit.nextWorkspace;
    const issuerId = asAuthorizationRecord(
      issuerSubmit.record,
    ).authorization.authorizationId;

    const verifierSubmit = applyOperation(workspace, {
      operation: "submit",
      target: "verifier",
      label: "age-gate",
    });
    workspace = verifierSubmit.nextWorkspace;
    const verifierId = asAuthorizationRecord(
      verifierSubmit.record,
    ).authorization.authorizationId;

    for (const operation of [
      {
        operation: "approve" as const,
        target: "issuer" as const,
        id: issuerId,
      },
      {
        operation: "activate" as const,
        target: "issuer" as const,
        id: issuerId,
      },
      {
        operation: "approve" as const,
        target: "verifier" as const,
        id: verifierId,
      },
      {
        operation: "activate" as const,
        target: "verifier" as const,
        id: verifierId,
      },
    ]) {
      workspace = applyWorkspaceOperation(workspace, operation);
    }

    const workspacePath = join(tempDir, "operator-workspace.json");
    await writeWorkspaceToFile(workspacePath, workspace);

    const server = await startServer(createWorkspaceFileSource(workspacePath));
    try {
      const summaryResponse = await fetch(`${server.url}/v1/registry/summary`);
      expect(summaryResponse.status).toBe(200);
      const summary = await summaryResponse.json();
      expect(summary.registryLabel).toBe("kanon-api");
      expect(summary.issuerCounts.active).toBe(1);
      expect(summary.verifierCounts.active).toBe(1);

      const registryResponse = await fetch(`${server.url}/v1/registry`);
      expect(registryResponse.status).toBe(200);
      const registry = await registryResponse.json();
      expect(registry.registryId).toBe(workspace.snapshot.registry.registryId);

      const healthResponse = await fetch(`${server.url}/health`);
      expect(healthResponse.status).toBe(200);
      const health = await healthResponse.json();
      expect(health.sourceMode).toBe("workspace");

      const listResponse = await fetch(
        `${server.url}/v1/authorizations/issuer?status=active`,
      );
      expect(listResponse.status).toBe(200);
      const list = await listResponse.json();
      expect(list.total).toBe(1);
      expect(list.entries[0].authorization.authorizationId).toBe(issuerId);

      const resolveResponse = await fetch(
        `${server.url}/v1/authorizations/resolve`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            role: "issuer",
            subjectDid: list.entries[0].authorization.subjectDid,
            resourceId: list.entries[0].authorization.resourceId,
          }),
        },
      );
      expect(resolveResponse.status).toBe(200);
      const resolved = await resolveResponse.json();
      expect(resolved.authorization.authorizationId).toBe(issuerId);

      const evaluateResponse = await fetch(
        `${server.url}/v1/authorizations/evaluate`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            role: "issuer",
            subjectDid: list.entries[0].authorization.subjectDid,
            resourceId: list.entries[0].authorization.resourceId,
            at: list.entries[0].authorization.activeFrom,
          }),
        },
      );
      expect(evaluateResponse.status).toBe(200);
      const evaluation = await evaluateResponse.json();
      expect(evaluation.entry.authorization.authorizationId).toBe(issuerId);
      expect(evaluation.statusAtTime).toBe("active");
      expect(evaluation.trustedAtTime).toBe(true);

      const evidenceResponse = await fetch(
        `${server.url}/v1/authorizations/issuer/${issuerId}/evidence`,
      );
      expect(evidenceResponse.status).toBe(200);
      const evidence = await evidenceResponse.json();
      expect(evidence.authorization.authorizationId).toBe(issuerId);

      const epochResolveResponse = await fetch(
        `${server.url}/v1/epochs/resolve?at=${encodeURIComponent(evidence.epoch.validFrom)}`,
      );
      expect(epochResolveResponse.status).toBe(200);
      const resolvedEpoch = await epochResolveResponse.json();
      expect(resolvedEpoch.epochId).toBe(evidence.epoch.epochId);

      const invalidEpochResolveResponse = await fetch(
        `${server.url}/v1/epochs/resolve?at=${encodeURIComponent("not-a-date")}`,
      );
      expect(invalidEpochResolveResponse.status).toBe(400);
      const invalidEpochResolveProblem = await invalidEpochResolveResponse.json();
      expect(invalidEpochResolveProblem.type).toMatch(/invalid-request$/);

      const trqpAuthorizationResponse = await fetch(
        `${server.url}/v1/trqp/authorizations/query`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            entity_id: list.entries[0].authorization.subjectDid,
            authority_id: workspace.snapshot.registry.registryDid,
            action: "issue",
            resource: list.entries[0].authorization.resourceId,
            context: { time: evidence.epoch.validFrom },
          }),
        },
      );
      expect(trqpAuthorizationResponse.status).toBe(200);
      const trqpAuthorization = await trqpAuthorizationResponse.json();
      expect(trqpAuthorization.authorized).toBe(true);

      const trqpEvidenceResponse = await fetch(
        `${server.url}/v1/trqp/authorizations/evidence`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            entity_id: list.entries[0].authorization.subjectDid,
            authority_id: workspace.snapshot.registry.registryDid,
            action: "issue",
            resource: list.entries[0].authorization.resourceId,
          }),
        },
      );
      expect(trqpEvidenceResponse.status).toBe(424);
      expect((await trqpEvidenceResponse.json()).type).toMatch(/epoch-evidence-unavailable$/);

      const historicalTrqpResponse = await fetch(
        `${server.url}/v1/trqp/authorizations/evidence`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            entity_id: list.entries[0].authorization.subjectDid,
            authority_id: workspace.snapshot.registry.registryDid,
            action: "issue",
            resource: list.entries[0].authorization.resourceId,
            context: { time: evidence.epoch.validFrom },
          }),
        },
      );
      expect(historicalTrqpResponse.status).toBe(200);
      const historicalTrqp = await historicalTrqpResponse.json();
      expect(historicalTrqp.authorized).toBe(true);
      expect(historicalTrqp.time_evaluated).toBe(evidence.epoch.validFrom);
      expect(historicalTrqp.bundle.epoch.epochId).toBe(evidence.epoch.epochId);

      const unanchoredTrqpResponse = await fetch(
        `${server.url}/v1/trqp/authorizations/query`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            entity_id: list.entries[0].authorization.subjectDid,
            authority_id: workspace.snapshot.registry.registryDid,
            action: "issue",
            resource: list.entries[0].authorization.resourceId,
            context: { time: "2026-05-21T00:00:00Z" },
          }),
        },
      );
      expect(unanchoredTrqpResponse.status).toBe(424);
      expect((await unanchoredTrqpResponse.json()).type).toMatch(/epoch-evidence-unavailable$/);

      const missingEpochResolveResponse = await fetch(
        `${server.url}/v1/epochs/resolve?at=${encodeURIComponent("2026-05-21T00:00:00Z")}`,
      );
      expect(missingEpochResolveResponse.status).toBe(404);
      const missingEpochResolveProblem = await missingEpochResolveResponse.json();
      expect(missingEpochResolveProblem.type).toMatch(/epoch-not-found$/);
    } finally {
      await server.close();
    }
  });

  it("uses a record-specific evidence epoch despite another overlapping epoch", async () => {
    const snapshot = createDemoSnapshot({ label: "epoch-mismatch" });
    const entry = snapshot.issuerEntries.find((candidate) => candidate.authorization.status === "active");
    if (entry === undefined) throw new Error("expected an active issuer");
    const evidenceEpoch = entry.evidence.epoch;
    const queryTime = new Date(Date.parse(evidenceEpoch.validFrom) + 1).toISOString();
    expect(Date.parse(queryTime)).toBeLessThan(Date.parse(evidenceEpoch.validUntil));
    const alteredSnapshot = {
      ...snapshot,
      epochs: [...snapshot.epochs, {
        ...evidenceEpoch,
        epochId: `${evidenceEpoch.epochId}:overlap`,
        validFrom: queryTime,
      }],
    };
    const server = await startServer(createInMemorySource(TrustRegistryOperatorSnapshotSchema.parse(alteredSnapshot)));
    try {
      const response = await fetch(`${server.url}/v1/trqp/authorizations/query`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          entity_id: entry.authorization.subjectDid,
          authority_id: snapshot.registry.registryDid,
          action: "issue",
          resource: entry.authorization.resourceId,
          context: { time: queryTime },
        }),
      });
      expect(response.status).toBe(200);
      expect((await response.json()).authorized).toBe(true);

      const unavailable = await fetch(`${server.url}/v1/trqp/authorizations/query`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          entity_id: entry.authorization.subjectDid,
          authority_id: snapshot.registry.registryDid,
          action: "issue",
          resource: entry.authorization.resourceId,
          context: { time: new Date(Date.parse(evidenceEpoch.validUntil) + 1).toISOString() },
        }),
      });
      expect(unavailable.status).toBe(424);
      expect((await unavailable.json()).type).toMatch(/epoch-evidence-unavailable$/);
    } finally {
      await server.close();
    }
  });

  it("does not project an expired active authorization as trusted at snapshot time", async () => {
    const snapshot = createDemoSnapshot({ label: "expired-current-trqp" });
    const entry = snapshot.issuerEntries.find((candidate) => candidate.authorization.status === "active");
    if (entry?.authorization.activeFrom === undefined) throw new Error("expected active issuer");
    const effectiveUntil = new Date(Date.parse(entry.authorization.activeFrom) + 1).toISOString();
    const generatedAt = entry.evidence.epoch.validUntil;
    expect(Date.parse(effectiveUntil)).toBeLessThan(Date.parse(generatedAt));
    const expired = {
      ...entry,
      authorization: { ...entry.authorization, effectiveUntil },
      evidence: {
        ...entry.evidence,
        authorization: { ...entry.authorization, effectiveUntil },
      },
    };
    const source = createTrqpSourceFromStateSource({
      mode: "memory",
      async loadSnapshot() {
        return {
          ...snapshot,
          generatedAt,
          issuerEntries: snapshot.issuerEntries.map((candidate) =>
            candidate.authorization.authorizationId === entry.authorization.authorizationId ? expired : candidate),
        };
      },
    });
    const decision = await source.getAuthorizationDecision({
      entity_id: entry.authorization.subjectDid,
      authority_id: snapshot.registry.registryDid,
      action: "issue",
      resource: entry.authorization.resourceId,
    });
    expect(decision).not.toBeNull();
    if (decision === null || "evidenceUnavailable" in decision) throw new Error("expected a current decision");
    expect(decision.statusAtTime).toBe("active");
    expect(decision.trustedAtTime).toBe(false);
    expect(decision.evaluatedAt).toBe(generatedAt);
  });

  it("submits and governs application workflows through workspace-backed write routes", async () => {
    const workspace = createOperatorWorkspace({ label: "kanon-write-api" });
    const workspacePath = join(tempDir, "write-workspace.json");
    await writeWorkspaceToFile(workspacePath, workspace);

    const server = await startServer(createWorkspaceFileSource(workspacePath));
    try {
      const issuerSubmitResponse = await fetch(
        `${server.url}/v1/applications`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            target: "issuer",
            label: "degree",
          }),
        },
      );
      expect(issuerSubmitResponse.status).toBe(201);
      const issuerSubmit = await issuerSubmitResponse.json();
      expect(issuerSubmit.recordKind).toBe("authorization");
      expect(issuerSubmit.entry.authorization.status).toBe("proposed");
      const issuerId = issuerSubmit.entry.authorization.authorizationId;

      const issuerApproveResponse = await fetch(
        `${server.url}/v1/applications/issuer/${issuerId}/approve`,
        {
          method: "POST",
        },
      );
      expect(issuerApproveResponse.status).toBe(200);
      const issuerApprove = await issuerApproveResponse.json();
      expect(issuerApprove.entry.authorization.status).toBe("authorized");

      const issuerActivateResponse = await fetch(
        `${server.url}/v1/applications/issuer/${issuerId}/activate`,
        {
          method: "POST",
        },
      );
      expect(issuerActivateResponse.status).toBe(200);
      const issuerActivate = await issuerActivateResponse.json();
      expect(issuerActivate.entry.authorization.status).toBe("active");

      const verifierSubmitResponse = await fetch(
        `${server.url}/v1/applications`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            target: "verifier",
            label: "age-gate",
          }),
        },
      );
      expect(verifierSubmitResponse.status).toBe(201);
      const verifierSubmit = await verifierSubmitResponse.json();
      expect(verifierSubmit.recordKind).toBe("authorization");
      expect(verifierSubmit.entry.authorization.status).toBe("proposed");
      const verifierId = verifierSubmit.entry.authorization.authorizationId;

      for (const action of ["approve", "activate", "suspend", "revoke", "archive"] as const) {
        const response = await fetch(
          `${server.url}/v1/applications/verifier/${verifierId}/${action}`,
          {
            method: "POST",
          },
        );
        expect(response.status).toBe(200);
      }

      const recognitionSubmitResponse = await fetch(
        `${server.url}/v1/applications`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            target: "recognition",
            label: "gaia-x",
          }),
        },
      );
      expect(recognitionSubmitResponse.status).toBe(201);
      const recognitionSubmit = await recognitionSubmitResponse.json();
      expect(recognitionSubmit.recordKind).toBe("recognition");
      expect(recognitionSubmit.entry.recognition.status).toBe("proposed");
      const recognitionId = recognitionSubmit.entry.recognition.recognitionId;

      const recognitionApproveResponse = await fetch(
        `${server.url}/v1/applications/recognition/${recognitionId}/approve`,
        {
          method: "POST",
        },
      );
      expect(recognitionApproveResponse.status).toBe(200);
      const recognitionApprove = await recognitionApproveResponse.json();
      expect(recognitionApprove.entry.recognition.status).toBe("authorized");

      const epochPublishResponse = await fetch(
        `${server.url}/v1/epochs/publish`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            label: "governed-epoch",
          }),
        },
      );
      expect(epochPublishResponse.status).toBe(200);
      const epochPublish = await epochPublishResponse.json();
      expect(epochPublish.recordKind).toBe("epoch");
      expect(epochPublish.epoch.epochId).toBe(epochPublish.currentEpochId);

      const activeIssuerListResponse = await fetch(
        `${server.url}/v1/authorizations/issuer?status=active`,
      );
      expect(activeIssuerListResponse.status).toBe(200);
      const activeIssuerList = await activeIssuerListResponse.json();
      expect(activeIssuerList.total).toBe(1);
      expect(activeIssuerList.entries[0].authorization.authorizationId).toBe(issuerId);

      const archivedVerifierListResponse = await fetch(
        `${server.url}/v1/authorizations/verifier?status=archived`,
      );
      expect(archivedVerifierListResponse.status).toBe(200);
      const archivedVerifierList = await archivedVerifierListResponse.json();
      expect(archivedVerifierList.total).toBe(1);
      expect(archivedVerifierList.entries[0].authorization.authorizationId).toBe(verifierId);
    } finally {
      await server.close();
    }
  }, 30_000);

  it("returns structured mutation problems and accepts epoch publish without a body", async () => {
    const workspace = createOperatorWorkspace({ label: "kanon-write-errors" });
    const workspacePath = join(tempDir, "write-errors-workspace.json");
    await writeWorkspaceToFile(workspacePath, workspace);

    const server = await startServer(createWorkspaceFileSource(workspacePath));
    try {
      const noBodyEpochPublishResponse = await fetch(
        `${server.url}/v1/epochs/publish`,
        {
          method: "POST",
        },
      );
      expect(noBodyEpochPublishResponse.status).toBe(200);
      const noBodyEpochPublish = await noBodyEpochPublishResponse.json();
      expect(noBodyEpochPublish.recordKind).toBe("epoch");

      const invalidTargetResponse = await fetch(
        `${server.url}/v1/applications/unknown/auth:issuer:missing:v1/approve`,
        {
          method: "POST",
        },
      );
      expect(invalidTargetResponse.status).toBe(400);
      const invalidTargetProblem = await invalidTargetResponse.json();
      expect(invalidTargetProblem.type).toMatch(/invalid-path-parameter$/);

      const missingAuthorizationResponse = await fetch(
        `${server.url}/v1/applications/issuer/auth:issuer:missing:v1/approve`,
        {
          method: "POST",
        },
      );
      expect(missingAuthorizationResponse.status).toBe(404);
      const missingAuthorizationProblem = await missingAuthorizationResponse.json();
      expect(missingAuthorizationProblem.type).toMatch(/authorization-not-found$/);

      const firstSubmitResponse = await fetch(
        `${server.url}/v1/applications`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            target: "issuer",
            label: "degree",
          }),
        },
      );
      expect(firstSubmitResponse.status).toBe(201);

      const duplicateSubmitResponse = await fetch(
        `${server.url}/v1/applications`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            target: "issuer",
            label: "degree",
          }),
        },
      );
      expect(duplicateSubmitResponse.status).toBe(409);
      const duplicateSubmitProblem = await duplicateSubmitResponse.json();
      expect(duplicateSubmitProblem.type).toMatch(/duplicate-application$/);
    } finally {
      await server.close();
    }
  });

  it("serves recognition and TRQP routes from a snapshot file", async () => {
    let workspace = createOperatorWorkspace({ label: "kanon-trqp" });

    const recognitionSubmit = applyOperation(workspace, {
      operation: "submit",
      target: "recognition",
      label: "gaia-x",
    });
    workspace = recognitionSubmit.nextWorkspace;
    const recognitionId = asRecognitionRecord(
      recognitionSubmit.record,
    ).recognition.recognitionId;

    for (const operation of [
      {
        operation: "approve" as const,
        target: "recognition" as const,
        id: recognitionId,
      },
      {
        operation: "activate" as const,
        target: "recognition" as const,
        id: recognitionId,
      },
    ]) {
      workspace = applyWorkspaceOperation(workspace, operation);
    }

    const snapshotPath = join(tempDir, "snapshot.json");
    await writeSnapshotToFile(snapshotPath, workspace.snapshot);

    const server = await startServer(createSnapshotFileSource(snapshotPath));
    try {
      const currentEpochResponse = await fetch(`${server.url}/v1/epochs/current`);
      expect(currentEpochResponse.status).toBe(200);
      const currentEpoch = await currentEpochResponse.json();
      expect(currentEpoch.epochId).toBe(workspace.snapshot.currentEpoch.epochId);

      const epochByIdResponse = await fetch(
        `${server.url}/v1/epochs/${workspace.snapshot.currentEpoch.epochId}`,
      );
      expect(epochByIdResponse.status).toBe(200);
      const epochById = await epochByIdResponse.json();
      expect(epochById.epochId).toBe(workspace.snapshot.currentEpoch.epochId);

      const recognitionResponse = await fetch(
        `${server.url}/v1/recognitions/${recognitionId}`,
      );
      expect(recognitionResponse.status).toBe(200);
      const recognition = await recognitionResponse.json();
      expect(recognition.recognition.recognitionId).toBe(recognitionId);

      const recognitionEvaluateResponse = await fetch(
        `${server.url}/v1/recognitions/evaluate`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            recognizedAuthorityDid: recognition.recognition.recognizedAuthorityDid,
            recognizedRegistryId: recognition.recognition.recognizedRegistryId,
            scopeResourceType: recognition.recognition.scope.resourceType,
            scopeResourceId: recognition.recognition.scope.resourceId,
            at: recognition.recognition.effectiveFrom,
          }),
        },
      );
      expect(recognitionEvaluateResponse.status).toBe(200);
      const recognitionEvaluation = await recognitionEvaluateResponse.json();
      expect(recognitionEvaluation.entry.recognition.recognitionId).toBe(recognitionId);
      expect(recognitionEvaluation.statusAtTime).toBe("active");
      expect(recognitionEvaluation.trustedAtTime).toBe(true);

      const metadataResponse = await fetch(
        `${server.url}/v1/trqp/metadata/${encodeURIComponent(workspace.snapshot.registry.registryDid)}`,
      );
      expect(metadataResponse.status).toBe(200);
      const metadata = await metadataResponse.json();
      expect(metadata.registry_id).toBe(workspace.snapshot.registry.registryId);

      const trqpQueryResponse = await fetch(
        `${server.url}/v1/trqp/recognitions/query`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            entity_id: recognition.recognition.recognizedAuthorityDid,
            authority_id: workspace.snapshot.registry.registryDid,
            action: recognition.recognition.scope.resourceType,
            resource: recognition.recognition.scope.resourceId,
            context: {
              recognized_registry_id:
                recognition.recognition.recognizedRegistryId,
              time: recognition.evidence.epoch.validFrom,
            },
          }),
        },
      );
      expect(trqpQueryResponse.status).toBe(200);
      const trqpQuery = await trqpQueryResponse.json();
      expect(trqpQuery.recognized).toBe(true);

      const trqpEvidenceResponse = await fetch(
        `${server.url}/v1/trqp/recognitions/evidence`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            entity_id: recognition.recognition.recognizedAuthorityDid,
            authority_id: workspace.snapshot.registry.registryDid,
            action: recognition.recognition.scope.resourceType,
            resource: recognition.recognition.scope.resourceId,
            context: {
              recognized_registry_id:
                recognition.recognition.recognizedRegistryId,
            },
          }),
        },
      );
      expect(trqpEvidenceResponse.status).toBe(424);
      expect((await trqpEvidenceResponse.json()).type).toMatch(/epoch-evidence-unavailable$/);
    } finally {
      await server.close();
    }
  });

  it("reloads workspace-backed state between requests and returns structured problems", async () => {
    let workspace = createOperatorWorkspace({ label: "kanon-reload" });
    const submitResult = applyOperation(workspace, {
      operation: "submit",
      target: "issuer",
      label: "passport",
    });
    workspace = submitResult.nextWorkspace;
    const issuerId = asAuthorizationRecord(
      submitResult.record,
    ).authorization.authorizationId;

    const workspacePath = join(tempDir, "reload-workspace.json");
    await writeWorkspaceToFile(workspacePath, workspace);

    const server = await startServer(createWorkspaceFileSource(workspacePath));
    try {
      const firstResponse = await fetch(
        `${server.url}/v1/authorizations/issuer?status=active`,
      );
      const firstList = await firstResponse.json();
      expect(firstList.total).toBe(0);

      workspace = applyWorkspaceOperation(workspace, {
        operation: "approve",
        target: "issuer",
        id: issuerId,
      });
      workspace = applyWorkspaceOperation(workspace, {
        operation: "activate",
        target: "issuer",
        id: issuerId,
      });
      await writeWorkspaceToFile(workspacePath, workspace);

      const secondResponse = await fetch(
        `${server.url}/v1/authorizations/issuer?status=active`,
      );
      const secondList = await secondResponse.json();
      expect(secondList.total).toBe(1);

      const badRequest = await fetch(
        `${server.url}/v1/authorizations/resolve`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            role: "issuer",
            subjectDid: "",
            resourceId: "scope",
          }),
        },
      );
      expect(badRequest.status).toBe(400);
      const badProblem = await badRequest.json();
      expect(badProblem.title).toMatch(/invalid request/i);
      expect(badProblem.type).toMatch(/invalid-request$/);

      const invalidJson = await fetch(
        `${server.url}/v1/trqp/authorizations/query`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: "{",
        },
      );
      expect(invalidJson.status).toBe(400);
      const invalidJsonProblem = await invalidJson.json();
      expect(invalidJsonProblem.type).toMatch(/invalid-json$/);

      const missingResponse = await fetch(
        `${server.url}/v1/recognitions/unknown-recognition`,
      );
      expect(missingResponse.status).toBe(404);
      const missingProblem = await missingResponse.json();
      expect(missingProblem.title).toMatch(/recognition not found/i);
      expect(missingProblem.type).toMatch(/recognition-not-found$/);
    } finally {
      await server.close();
    }
  });

  it("serves the same routes from an in-memory source", async () => {
    const workspace = createOperatorWorkspace({ label: "kanon-memory" });
    const server = await startServer(createInMemorySource(workspace.snapshot));
    try {
      const preflightResponse = await fetch(`${server.url}/v1/applications`, {
        method: "OPTIONS",
      });
      expect(preflightResponse.status).toBe(204);
      expect(preflightResponse.headers.get("access-control-allow-origin")).toBe("*");

      const healthResponse = await fetch(`${server.url}/health`);
      expect(healthResponse.status).toBe(200);
      expect(healthResponse.headers.get("access-control-allow-origin")).toBe("*");
      const health = await healthResponse.json();
      expect(health.sourceMode).toBe("memory");

      const summaryResponse = await fetch(`${server.url}/v1/registry/summary`);
      expect(summaryResponse.status).toBe(200);
      const summary = await summaryResponse.json();
      expect(summary.registryLabel).toBe("kanon-memory");
    } finally {
      await server.close();
    }
  });

  it("rejects workspace mutation routes for non-workspace sources", async () => {
    const workspace = createOperatorWorkspace({ label: "kanon-readonly" });
    const snapshotPath = join(tempDir, "readonly-snapshot.json");
    await writeSnapshotToFile(snapshotPath, workspace.snapshot);

    const server = await startServer(createSnapshotFileSource(snapshotPath));
    try {
      const response = await fetch(`${server.url}/v1/applications`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          target: "issuer",
          label: "degree",
        }),
      });
      expect(response.status).toBe(409);
      const problem = await response.json();
      expect(problem.type).toMatch(/workspace-source-required$/);
    } finally {
      await server.close();
    }
  });
});
