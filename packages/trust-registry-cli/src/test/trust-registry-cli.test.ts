import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { runCli } from "../cli.js";
import { loadSnapshotFromFile } from "../snapshot.js";

const CLI_TEST_TIMEOUT_MS = 20_000;

const captureCli = async (argv: readonly string[]) => {
  const stdout: string[] = [];
  const stderr: string[] = [];

  const exitCode = await runCli(argv, {
    stdout: (value) => stdout.push(value),
    stderr: (value) => stderr.push(value),
  });

  return {
    exitCode,
    stdout: stdout.join(""),
    stderr: stderr.join(""),
  };
};

describe("trust registry operator CLI", () => {
  it(
    "creates a deterministic demo snapshot and summarizes it as JSON",
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
      const snapshotPath = join(directory, "demo-snapshot.json");

      const initResult = await captureCli([
        "init-demo",
        "--output",
        snapshotPath,
        "--label",
        "operator",
      ]);
      expect(initResult.exitCode).toBe(0);

      const snapshot = await loadSnapshotFromFile(snapshotPath);
      expect(snapshot.registryLabel).toBe("operator");
      expect(snapshot.issuerEntries).toHaveLength(2);
      expect(snapshot.verifierEntries).toHaveLength(2);
      expect(snapshot.recognitionEntries).toHaveLength(2);

      const summaryResult = await captureCli([
        "summary",
        "--snapshot",
        snapshotPath,
        "--json",
      ]);
      expect(summaryResult.exitCode).toBe(0);

      const summary = JSON.parse(summaryResult.stdout) as {
        issuerCounts: { active: number; archived: number };
        verifierCounts: { active: number; archived: number };
        recognitionCounts: { active: number; archived: number };
      };
      expect(summary.issuerCounts.active).toBe(1);
      expect(summary.issuerCounts.archived).toBe(1);
      expect(summary.verifierCounts.active).toBe(1);
      expect(summary.verifierCounts.archived).toBe(1);
      expect(summary.recognitionCounts.active).toBe(1);
      expect(summary.recognitionCounts.archived).toBe(1);
    },
    CLI_TEST_TIMEOUT_MS,
  );

  it(
    "lists and inspects issuer records from the saved snapshot",
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
      const snapshotPath = join(directory, "demo-snapshot.json");

      await captureCli(["init-demo", "--output", snapshotPath]);
      const snapshot = await loadSnapshotFromFile(snapshotPath);
      const issuerId = snapshot.issuerEntries[0]?.authorization.authorizationId;
      if (issuerId === undefined) {
        throw new Error("expected issuer authorization in demo snapshot");
      }

      const listResult = await captureCli([
        "list",
        "--snapshot",
        snapshotPath,
        "--kind",
        "issuer",
        "--json",
      ]);
      expect(listResult.exitCode).toBe(0);
      const listed = JSON.parse(listResult.stdout) as Array<{
        authorization: { authorizationId: string };
      }>;
      expect(listed).toHaveLength(2);
      expect(listed[0]?.authorization.authorizationId).toBe(issuerId);

      const inspectResult = await captureCli([
        "inspect",
        "--snapshot",
        snapshotPath,
        "--kind",
        "issuer",
        "--id",
        issuerId,
      ]);
      expect(inspectResult.exitCode).toBe(0);
      const inspected = JSON.parse(inspectResult.stdout) as {
        authorization: { authorizationId: string; role: string };
        evidence: { registryId: string };
      };
      expect(inspected.authorization.authorizationId).toBe(issuerId);
      expect(inspected.authorization.role).toBe("issuer");
      expect(inspected.evidence.registryId).toBe(snapshot.registry.registryId);
    },
    CLI_TEST_TIMEOUT_MS,
  );

  it("exports anchored evidence bundles for operator use", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
    const snapshotPath = join(directory, "demo-snapshot.json");
    const evidencePath = join(directory, "issuer-evidence.json");

    await captureCli(["init-demo", "--output", snapshotPath]);
    const snapshot = await loadSnapshotFromFile(snapshotPath);
    const issuerId = snapshot.issuerEntries[0]?.authorization.authorizationId;
    if (issuerId === undefined) {
      throw new Error("expected issuer authorization in demo snapshot");
    }

    const exportResult = await captureCli([
      "export-evidence",
      "--snapshot",
      snapshotPath,
      "--kind",
      "issuer",
      "--id",
      issuerId,
      "--output",
      evidencePath,
    ]);
    expect(exportResult.exitCode).toBe(0);

    const bundle = JSON.parse(await readFile(evidencePath, "utf8")) as {
      authorization: { authorizationId: string };
      epoch: { epochId: string };
    };
    expect(bundle.authorization.authorizationId).toBe(issuerId);
    expect(
      snapshot.epochs.some((epoch) => epoch.epochId === bundle.epoch.epochId),
    ).toBe(true);
  }, CLI_TEST_TIMEOUT_MS);

  it(
    "emits a full human-readable audit report from the saved snapshot",
    async () => {
    const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
    const snapshotPath = join(directory, "demo-snapshot.json");

    await captureCli(["init-demo", "--output", snapshotPath, "--label", "audit"]);

    const reportResult = await captureCli([
      "report",
      "--snapshot",
      snapshotPath,
      "--kind",
      "full",
    ]);
    expect(reportResult.exitCode).toBe(0);
    expect(reportResult.stdout).toContain("Trust Registry Audit Report");
    expect(reportResult.stdout).toContain("Registry: registry:audit:trusted");
    expect(reportResult.stdout).toContain("Policy");
    expect(reportResult.stdout).toContain("Policy templates:");
    expect(reportResult.stdout).toContain("Decision bindings:");
    expect(reportResult.stdout).toContain("Issuer Authorizations");
    expect(reportResult.stdout).toContain("Verifier Authorizations");
    expect(reportResult.stdout).toContain("Recognitions");
    expect(reportResult.stdout).toContain("Epoch History");
    },
    CLI_TEST_TIMEOUT_MS,
  );

  it("writes a focused issuer audit report to disk", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
    const snapshotPath = join(directory, "demo-snapshot.json");
    const reportPath = join(directory, "issuer-report.txt");

    await captureCli(["init-demo", "--output", snapshotPath]);
    const snapshot = await loadSnapshotFromFile(snapshotPath);
    const issuerId = snapshot.issuerEntries[1]?.authorization.authorizationId;
    if (issuerId === undefined) {
      throw new Error("expected issuer authorization in demo snapshot");
    }

    const reportResult = await captureCli([
      "report",
      "--snapshot",
      snapshotPath,
      "--kind",
      "issuer",
      "--id",
      issuerId,
      "--output",
      reportPath,
    ]);
    expect(reportResult.exitCode).toBe(0);

    const report = await readFile(reportPath, "utf8");
    expect(report).toContain("Trust Registry Issuer Authorization Audit");
    expect(report).toContain(`Authorization ID: ${issuerId}`);
    expect(report).toContain("Status: archived");
    expect(report).toContain("Timeline:");
    expect(report).toContain("proposedAt:");
    expect(report).toContain("archivedAt:");
  }, CLI_TEST_TIMEOUT_MS);

  it("fails when a focused report targets an unknown issuer authorization", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
    const snapshotPath = join(directory, "demo-snapshot.json");

    await captureCli(["init-demo", "--output", snapshotPath]);

    const reportResult = await captureCli([
      "report",
      "--snapshot",
      snapshotPath,
      "--kind",
      "issuer",
      "--id",
      "auth:issuer:missing:v1",
    ]);

    expect(reportResult.exitCode).toBe(1);
    expect(reportResult.stderr).toContain(
      "unknown issuer authorization: auth:issuer:missing:v1",
    );
  }, CLI_TEST_TIMEOUT_MS);

  it(
    "manages an issuer workflow inside a mutable operator workspace",
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
      const workspacePath = join(directory, "workspace.json");

      const initResult = await captureCli([
        "init-workspace",
        "--workspace",
        workspacePath,
        "--label",
        "mutable",
      ]);
      expect(initResult.exitCode).toBe(0);

      const submitResult = await captureCli([
        "submit",
        "--workspace",
        workspacePath,
        "--kind",
        "issuer",
        "--label",
        "passport",
        "--json",
      ]);
      expect(submitResult.exitCode).toBe(0);
      const submitted = JSON.parse(submitResult.stdout) as {
        authorization: { authorizationId: string; status: string };
      };
      expect(submitted.authorization.status).toBe("proposed");

      const authorizationId = submitted.authorization.authorizationId;
      for (const command of ["approve", "activate"] as const) {
        const result = await captureCli([
          command,
          "--workspace",
          workspacePath,
          "--kind",
          "issuer",
          "--id",
          authorizationId,
          "--json",
        ]);
        expect(result.exitCode).toBe(0);
      }

      const summaryResult = await captureCli([
        "summary",
        "--workspace",
        workspacePath,
        "--json",
      ]);
      expect(summaryResult.exitCode).toBe(0);
      const summary = JSON.parse(summaryResult.stdout) as {
        issuerCounts: { active: number };
        epochCount: number;
      };
      expect(summary.issuerCounts.active).toBe(1);
      expect(summary.epochCount).toBeGreaterThanOrEqual(1);

      const evidenceResult = await captureCli([
        "export-evidence",
        "--workspace",
        workspacePath,
        "--kind",
        "issuer",
        "--id",
        authorizationId,
      ]);
      expect(evidenceResult.exitCode).toBe(0);
      const evidence = JSON.parse(evidenceResult.stdout) as {
        authorization: { status: string };
      };
      expect(evidence.authorization.status).toBe("active");

      const epochResult = await captureCli([
        "publish-epoch",
        "--workspace",
        workspacePath,
        "--json",
      ]);
      expect(epochResult.exitCode).toBe(0);
      const epoch = JSON.parse(epochResult.stdout) as { epochId: string };
      expect(epoch.epochId).toContain("epoch:");
    },
    CLI_TEST_TIMEOUT_MS,
  );

  it(
    "manages verifier and recognition workflows inside a mutable operator workspace",
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "tr-cli-"));
      const workspacePath = join(directory, "workspace.json");

      await captureCli(["init-workspace", "--workspace", workspacePath]);

      const verifierSubmit = await captureCli([
        "submit",
        "--workspace",
        workspacePath,
        "--kind",
        "verifier",
        "--label",
        "employment",
        "--json",
      ]);
      const verifierId = (
        JSON.parse(verifierSubmit.stdout) as {
          authorization: { authorizationId: string };
        }
      ).authorization.authorizationId;

      for (const command of ["approve", "activate", "suspend", "revoke", "archive"] as const) {
        const result = await captureCli([
          command,
          "--workspace",
          workspacePath,
          "--kind",
          "verifier",
          "--id",
          verifierId,
          "--json",
        ]);
        expect(result.exitCode).toBe(0);
      }

      const recognitionSubmit = await captureCli([
        "submit",
        "--workspace",
        workspacePath,
        "--kind",
        "recognition",
        "--label",
        "gaia-x",
        "--json",
      ]);
      const recognitionId = (
        JSON.parse(recognitionSubmit.stdout) as {
          recognition: { recognitionId: string };
        }
      ).recognition.recognitionId;

      for (const command of ["approve", "activate"] as const) {
        const result = await captureCli([
          command,
          "--workspace",
          workspacePath,
          "--kind",
          "recognition",
          "--id",
          recognitionId,
          "--json",
        ]);
        expect(result.exitCode).toBe(0);
      }

      const listResult = await captureCli([
        "list",
        "--workspace",
        workspacePath,
        "--kind",
        "recognition",
        "--json",
      ]);
      expect(listResult.exitCode).toBe(0);
      const recognitions = JSON.parse(listResult.stdout) as Array<{
        recognition: { recognitionId: string; status: string };
      }>;
      expect(recognitions[0]?.recognition.recognitionId).toBe(recognitionId);
      expect(recognitions[0]?.recognition.status).toBe("active");

      const reportResult = await captureCli([
        "report",
        "--workspace",
        workspacePath,
        "--kind",
        "full",
      ]);
      expect(reportResult.exitCode).toBe(0);
      expect(reportResult.stdout).toContain("Policy templates:");
      expect(reportResult.stdout).toContain("Decision bindings:");
      expect(reportResult.stdout).toContain("template=policy-template:");
    },
    CLI_TEST_TIMEOUT_MS,
  );
});
