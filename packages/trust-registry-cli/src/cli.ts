import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { parseArgs } from "node:util";

import { createDemoSnapshot } from "./demo-snapshot.js";
import { serializeJson } from "./model.js";
import { renderAuditReport, type AuditReportKind } from "./report.js";
import {
  buildSnapshotSummary,
  exportEvidenceBundle,
  findEpoch,
  inspectEpochAtTimestamp,
  inspectIssuerEntryAtTimestamp,
  inspectRecognitionEntryAtTimestamp,
  inspectVerifierEntryAtTimestamp,
  listEpochs,
  listIssuerEntries,
  listRecognitionEntries,
  listVerifierEntries,
  loadSnapshotFromFile,
  renderAuthorizationList,
  renderEpochList,
  renderRecognitionList,
  renderSnapshotRecord,
  renderSummary,
  renderVerifierList,
  writeSnapshotToFile,
  type SnapshotRecordKind,
} from "./snapshot.js";
import {
  applyWorkspaceOperation,
  createOperatorWorkspace,
  loadWorkspaceFromFile,
  resolveWorkspaceOperationRecord,
  writeWorkspaceToFile,
} from "./workspace.js";
import type {
  MutableSnapshotTarget,
  TrustRegistryOperatorWorkspaceOperation,
} from "./model.js";

type CommandName =
  | "init-demo"
  | "init-workspace"
  | "summary"
  | "list"
  | "inspect"
  | "export-evidence"
  | "report"
  | "submit"
  | "approve"
  | "activate"
  | "suspend"
  | "revoke"
  | "archive"
  | "publish-epoch"
  | "help";

type CliIo = {
  stderr: (value: string) => void;
  stdout: (value: string) => void;
};

const defaultIo: CliIo = {
  stdout: (value) => process.stdout.write(value),
  stderr: (value) => process.stderr.write(value),
};

const HELP_TEXT = `Trust Registry operator CLI

Commands:
  init-demo        Create a deterministic local snapshot from the simulator harness
  init-workspace   Create a mutable local operator workspace backed by governed CLI actions
  summary          Summarize a saved snapshot
  list             List issuer, verifier, recognition, or epoch records
  inspect          Print a specific snapshot record as JSON
  export-evidence  Export an anchored evidence bundle as JSON
  report           Emit a human-readable audit report from a saved snapshot
  submit           Submit an issuer, verifier, or recognition application into a workspace
  approve          Approve a submitted workspace application
  activate         Activate an approved workspace application
  suspend          Suspend an active workspace record
  revoke           Revoke a suspended or active workspace record
  archive          Archive a revoked or historical workspace record
  publish-epoch    Publish the current workspace registry epoch anchor

Examples:
  trust-registry init-demo --output ./artifacts/trust-registry/demo.json
  trust-registry init-workspace --workspace ./artifacts/trust-registry/workspace.json
  trust-registry summary --snapshot ./artifacts/trust-registry/demo.json
  trust-registry summary --workspace ./artifacts/trust-registry/workspace.json
  trust-registry list --snapshot ./artifacts/trust-registry/demo.json --kind issuer
  trust-registry submit --workspace ./artifacts/trust-registry/workspace.json --kind issuer --label passport
  trust-registry approve --workspace ./artifacts/trust-registry/workspace.json --kind issuer --id auth:issuer:passport:v1
  trust-registry activate --workspace ./artifacts/trust-registry/workspace.json --kind issuer --id auth:issuer:passport:v1
  trust-registry suspend --workspace ./artifacts/trust-registry/workspace.json --kind verifier --id auth:verifier:employment:v1
  trust-registry revoke --workspace ./artifacts/trust-registry/workspace.json --kind verifier --id auth:verifier:employment:v1
  trust-registry archive --workspace ./artifacts/trust-registry/workspace.json --kind verifier --id auth:verifier:employment:v1
  trust-registry inspect --snapshot ./artifacts/trust-registry/demo.json --kind epoch
  trust-registry inspect --snapshot ./artifacts/trust-registry/demo.json --kind issuer --id auth:issuer:passport:v1 --at 2026-05-20T00:30:00Z
  trust-registry export-evidence --snapshot ./artifacts/trust-registry/demo.json --kind issuer --id auth:issuer:passport:v1
  trust-registry report --snapshot ./artifacts/trust-registry/demo.json --kind full
  trust-registry report --snapshot ./artifacts/trust-registry/demo.json --kind issuer --id auth:issuer:passport:v1
  trust-registry publish-epoch --workspace ./artifacts/trust-registry/workspace.json
`;

const parseKind = (value: string | undefined): SnapshotRecordKind => {
  switch (value) {
    case "registry":
    case "policy":
    case "issuer":
    case "verifier":
    case "recognition":
    case "epoch":
      return value;
    default:
      throw new Error(`unsupported --kind value: ${value ?? "<missing>"}`);
  }
};

const parseEvidenceKind = (
  value: string | undefined,
): "issuer" | "verifier" | "recognition" => {
  const kind = parseKind(value);
  if (kind === "registry" || kind === "policy" || kind === "epoch") {
    throw new Error(`unsupported evidence kind: ${kind}`);
  }

  return kind;
};

const parseMutableTarget = (value: string | undefined): MutableSnapshotTarget => {
  switch (value) {
    case "issuer":
    case "verifier":
    case "recognition":
      return value;
    default:
      throw new Error(`unsupported mutable --kind value: ${value ?? "<missing>"}`);
  }
};

const parseAuditReportKind = (
  value: string | undefined,
): AuditReportKind => {
  switch (value) {
    case undefined:
    case "full":
      return "full";
    case "registry":
    case "policy":
    case "issuer":
    case "verifier":
    case "recognition":
    case "epoch":
      return value;
    default:
      throw new Error(`unsupported report kind: ${value}`);
  }
};

const requireStringOption = (
  value: string | boolean | undefined,
  flag: string,
): string => {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${flag} is required`);
  }

  return value;
};

const validateReportIdUsage = (
  kind: AuditReportKind,
  id: string | undefined,
): void => {
  if (id === undefined) {
    return;
  }

  if (kind === "full" || kind === "registry" || kind === "policy") {
    throw new Error(`--id is not supported for ${kind} reports`);
  }
};

const isHelpRequest = (value: string | undefined): boolean =>
  value === undefined || value === "help" || value === "--help" || value === "-h";

const writeJson = (io: CliIo, value: unknown): void => {
  io.stdout(serializeJson(value));
};

const loadSnapshotState = async (input: {
  snapshot: string | boolean | undefined;
  workspace: string | boolean | undefined;
}) => {
  const snapshotPath = typeof input.snapshot === "string" ? input.snapshot : undefined;
  const workspacePath =
    typeof input.workspace === "string" ? input.workspace : undefined;

  if (snapshotPath !== undefined && workspacePath !== undefined) {
    throw new Error("use either --snapshot or --workspace, not both");
  }
  if (snapshotPath !== undefined) {
    return await loadSnapshotFromFile(snapshotPath);
  }
  if (workspacePath !== undefined) {
    return (await loadWorkspaceFromFile(workspacePath)).snapshot;
  }

  throw new Error("one of --snapshot or --workspace is required");
};

const runInitDemo = async (argv: readonly string[], io: CliIo): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      output: { type: "string" },
      label: { type: "string" },
    },
    strict: true,
  });
  const outputPath = requireStringOption(parsed.values.output, "--output");
  const snapshot = createDemoSnapshot(
    typeof parsed.values.label === "string"
      ? { label: parsed.values.label }
      : {},
  );

  await writeSnapshotToFile(outputPath, snapshot);
  io.stdout(`Wrote demo snapshot to ${outputPath}\n`);
  return 0;
};

const runInitWorkspace = async (
  argv: readonly string[],
  io: CliIo,
): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      workspace: { type: "string" },
      label: { type: "string" },
    },
    strict: true,
  });
  const workspacePath = requireStringOption(parsed.values.workspace, "--workspace");
  const workspace = createOperatorWorkspace(
    typeof parsed.values.label === "string"
      ? { label: parsed.values.label }
      : {},
  );

  await writeWorkspaceToFile(workspacePath, workspace);
  io.stdout(`Wrote operator workspace to ${workspacePath}\n`);
  return 0;
};

const runSummary = async (argv: readonly string[], io: CliIo): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      snapshot: { type: "string" },
      workspace: { type: "string" },
      json: { type: "boolean" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotState({
    snapshot: parsed.values.snapshot,
    workspace: parsed.values.workspace,
  });
  const summary = buildSnapshotSummary(snapshot);

  if (parsed.values.json) {
    writeJson(io, summary);
    return 0;
  }

  io.stdout(`${renderSummary(summary)}\n`);
  return 0;
};

const runList = async (argv: readonly string[], io: CliIo): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      snapshot: { type: "string" },
      workspace: { type: "string" },
      kind: { type: "string" },
      json: { type: "boolean" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotState({
    snapshot: parsed.values.snapshot,
    workspace: parsed.values.workspace,
  });
  const kind = parseKind(
    typeof parsed.values.kind === "string" ? parsed.values.kind : undefined,
  );

  switch (kind) {
    case "registry":
    case "policy":
      throw new Error(`list does not support kind: ${kind}`);
    case "issuer": {
      const entries = listIssuerEntries(snapshot);
      if (parsed.values.json) {
        writeJson(io, entries);
      } else {
        io.stdout(`${renderAuthorizationList(entries)}\n`);
      }
      return 0;
    }
    case "verifier": {
      const entries = listVerifierEntries(snapshot);
      if (parsed.values.json) {
        writeJson(io, entries);
      } else {
        io.stdout(`${renderVerifierList(entries)}\n`);
      }
      return 0;
    }
    case "recognition": {
      const entries = listRecognitionEntries(snapshot);
      if (parsed.values.json) {
        writeJson(io, entries);
      } else {
        io.stdout(`${renderRecognitionList(entries)}\n`);
      }
      return 0;
    }
    case "epoch": {
      const epochs = listEpochs(snapshot);
      if (parsed.values.json) {
        writeJson(io, epochs);
      } else {
        io.stdout(`${renderEpochList(epochs, snapshot.currentEpoch.epochId)}\n`);
      }
      return 0;
    }
  }
};

const runInspect = async (argv: readonly string[], io: CliIo): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      snapshot: { type: "string" },
      workspace: { type: "string" },
      kind: { type: "string" },
      id: { type: "string" },
      at: { type: "string" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotState({
    snapshot: parsed.values.snapshot,
    workspace: parsed.values.workspace,
  });
  const kind = parseKind(
    typeof parsed.values.kind === "string" ? parsed.values.kind : undefined,
  );
  const id = typeof parsed.values.id === "string" ? parsed.values.id : undefined;
  const evaluatedAt =
    typeof parsed.values.at === "string" ? parsed.values.at : undefined;

  if (evaluatedAt !== undefined) {
    switch (kind) {
      case "registry":
      case "policy":
        throw new Error(`inspect does not support --at for kind: ${kind}`);
      case "issuer":
        writeJson(io, inspectIssuerEntryAtTimestamp(snapshot, requireStringOption(id, "--id"), evaluatedAt));
        return 0;
      case "verifier":
        writeJson(io, inspectVerifierEntryAtTimestamp(snapshot, requireStringOption(id, "--id"), evaluatedAt));
        return 0;
      case "recognition":
        writeJson(io, inspectRecognitionEntryAtTimestamp(snapshot, requireStringOption(id, "--id"), evaluatedAt));
        return 0;
      case "epoch":
        writeJson(io, inspectEpochAtTimestamp(snapshot, evaluatedAt));
        return 0;
    }
  }

  writeJson(io, renderSnapshotRecord(snapshot, kind, id));
  return 0;
};

const runExportEvidence = async (
  argv: readonly string[],
  io: CliIo,
): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      snapshot: { type: "string" },
      workspace: { type: "string" },
      kind: { type: "string" },
      id: { type: "string" },
      output: { type: "string" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotState({
    snapshot: parsed.values.snapshot,
    workspace: parsed.values.workspace,
  });
  const kind = parseEvidenceKind(
    typeof parsed.values.kind === "string" ? parsed.values.kind : undefined,
  );
  const bundle = exportEvidenceBundle(
    snapshot,
    kind,
    requireStringOption(parsed.values.id, "--id"),
  );
  const serialized = serializeJson(bundle);

  if (typeof parsed.values.output === "string") {
    await mkdir(dirname(parsed.values.output), { recursive: true });
    await writeFile(parsed.values.output, serialized, "utf8");
    io.stdout(`Wrote evidence bundle to ${parsed.values.output}\n`);
    return 0;
  }

  io.stdout(serialized);
  return 0;
};

const runReport = async (argv: readonly string[], io: CliIo): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      snapshot: { type: "string" },
      workspace: { type: "string" },
      kind: { type: "string" },
      id: { type: "string" },
      output: { type: "string" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotState({
    snapshot: parsed.values.snapshot,
    workspace: parsed.values.workspace,
  });
  const kind = parseAuditReportKind(
    typeof parsed.values.kind === "string" ? parsed.values.kind : undefined,
  );
  const id = typeof parsed.values.id === "string" ? parsed.values.id : undefined;
  validateReportIdUsage(kind, id);
  const report = renderAuditReport(
    snapshot,
    kind,
    id,
  );

  if (typeof parsed.values.output === "string") {
    await mkdir(dirname(parsed.values.output), { recursive: true });
    await writeFile(parsed.values.output, report, "utf8");
    io.stdout(`Wrote audit report to ${parsed.values.output}\n`);
    return 0;
  }

  io.stdout(report);
  return 0;
};

const runWorkspaceMutation = async (
  workspacePath: string,
  operation: TrustRegistryOperatorWorkspaceOperation,
  io: CliIo,
  json = false,
): Promise<number> => {
  const workspace = await loadWorkspaceFromFile(workspacePath);
  const updatedWorkspace = applyWorkspaceOperation(workspace, operation);
  await writeWorkspaceToFile(workspacePath, updatedWorkspace);
  const result = resolveWorkspaceOperationRecord(updatedWorkspace, operation);

  if (json) {
    writeJson(io, result);
    return 0;
  }

  switch (operation.operation) {
    case "publish-epoch":
      io.stdout(`Published workspace epoch ${updatedWorkspace.snapshot.currentEpoch.epochId}\n`);
      return 0;
    default:
      io.stdout(`Updated workspace ${workspacePath}\n`);
      return 0;
  }
};

const runSubmit = async (argv: readonly string[], io: CliIo): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      workspace: { type: "string" },
      kind: { type: "string" },
      label: { type: "string" },
      json: { type: "boolean" },
    },
    strict: true,
  });

  return await runWorkspaceMutation(
    requireStringOption(parsed.values.workspace, "--workspace"),
    {
      operation: "submit",
      target: parseMutableTarget(
        typeof parsed.values.kind === "string" ? parsed.values.kind : undefined,
      ),
      label: requireStringOption(parsed.values.label, "--label"),
    },
    io,
    Boolean(parsed.values.json),
  );
};

const runWorkspaceTargetOperation = async (
  argv: readonly string[],
  io: CliIo,
  operation:
    | "approve"
    | "activate"
    | "suspend"
    | "revoke"
    | "archive",
): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      workspace: { type: "string" },
      kind: { type: "string" },
      id: { type: "string" },
      json: { type: "boolean" },
    },
    strict: true,
  });

  return await runWorkspaceMutation(
    requireStringOption(parsed.values.workspace, "--workspace"),
    {
      operation,
      target: parseMutableTarget(
        typeof parsed.values.kind === "string" ? parsed.values.kind : undefined,
      ),
      id: requireStringOption(parsed.values.id, "--id"),
    },
    io,
    Boolean(parsed.values.json),
  );
};

const runPublishEpoch = async (
  argv: readonly string[],
  io: CliIo,
): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      workspace: { type: "string" },
      label: { type: "string" },
      json: { type: "boolean" },
    },
    strict: true,
  });

  return await runWorkspaceMutation(
    requireStringOption(parsed.values.workspace, "--workspace"),
    {
      operation: "publish-epoch",
      ...(typeof parsed.values.label === "string" ? { label: parsed.values.label } : {}),
    },
    io,
    Boolean(parsed.values.json),
  );
};

export const runCli = async (
  argv: readonly string[],
  io: CliIo = defaultIo,
): Promise<number> => {
  const [command, ...rest] = argv;
  if (isHelpRequest(command)) {
    io.stdout(HELP_TEXT);
    return 0;
  }

  try {
    switch (command as CommandName) {
      case "init-demo":
        return await runInitDemo(rest, io);
      case "init-workspace":
        return await runInitWorkspace(rest, io);
      case "summary":
        return await runSummary(rest, io);
      case "list":
        return await runList(rest, io);
      case "inspect":
        return await runInspect(rest, io);
      case "export-evidence":
        return await runExportEvidence(rest, io);
      case "report":
        return await runReport(rest, io);
      case "submit":
        return await runSubmit(rest, io);
      case "approve":
        return await runWorkspaceTargetOperation(rest, io, "approve");
      case "activate":
        return await runWorkspaceTargetOperation(rest, io, "activate");
      case "suspend":
        return await runWorkspaceTargetOperation(rest, io, "suspend");
      case "revoke":
        return await runWorkspaceTargetOperation(rest, io, "revoke");
      case "archive":
        return await runWorkspaceTargetOperation(rest, io, "archive");
      case "publish-epoch":
        return await runPublishEpoch(rest, io);
      case "help":
        io.stdout(HELP_TEXT);
        return 0;
      default:
        throw new Error(`unknown command: ${command}`);
    }
  } catch (error) {
    io.stderr(
      `${error instanceof Error ? error.message : String(error)}\n\n${HELP_TEXT}`,
    );
    return 1;
  }
};

export const readCurrentEpochFromSnapshot = async (
  snapshotPath: string,
) => findEpoch(await loadSnapshotFromFile(snapshotPath));
