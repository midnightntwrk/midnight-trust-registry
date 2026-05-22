import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  applyWorkspaceOperation,
  createOperatorWorkspace,
  resolveWorkspaceOperationRecord,
  writeSnapshotToFile,
  writeWorkspaceToFile,
  type TrustRegistryAuthorizationSnapshotEntry,
  type TrustRegistryRecognitionSnapshotEntry,
  type TrustRegistryOperatorWorkspace,
} from "@midnight-ntwrk/trust-registry-cli";

import {
  createInMemorySource,
  createSnapshotFileSource,
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

      const evidenceResponse = await fetch(
        `${server.url}/v1/authorizations/issuer/${issuerId}/evidence`,
      );
      expect(evidenceResponse.status).toBe(200);
      const evidence = await evidenceResponse.json();
      expect(evidence.authorization.authorizationId).toBe(issuerId);

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
      expect(trqpEvidenceResponse.status).toBe(200);
      const trqpEvidence = await trqpEvidenceResponse.json();
      expect(trqpEvidence.bundle.authorization.authorizationId).toBe(issuerId);
    } finally {
      await server.close();
    }
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
      expect(trqpEvidenceResponse.status).toBe(200);
      const trqpEvidence = await trqpEvidenceResponse.json();
      expect(trqpEvidence.bundle.recognition.recognitionId).toBe(recognitionId);
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
      const healthResponse = await fetch(`${server.url}/health`);
      expect(healthResponse.status).toBe(200);
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
