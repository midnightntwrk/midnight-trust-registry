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

import { createSnapshotFileSource, createWorkspaceFileSource } from "../source.js";
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

      const missingResponse = await fetch(
        `${server.url}/v1/recognitions/unknown-recognition`,
      );
      expect(missingResponse.status).toBe(404);
      const missingProblem = await missingResponse.json();
      expect(missingProblem.title).toMatch(/recognition not found/i);
    } finally {
      await server.close();
    }
  });
});
