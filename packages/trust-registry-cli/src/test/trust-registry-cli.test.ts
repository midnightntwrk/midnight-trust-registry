import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { runCli } from "../cli.js";
import { loadSnapshotFromFile } from "../snapshot.js";

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
  it("creates a deterministic demo snapshot and summarizes it as JSON", async () => {
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
  });

  it("lists and inspects issuer records from the saved snapshot", async () => {
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
  });

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
  });
});
