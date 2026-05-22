import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { parseArgs } from "node:util";

import { createDemoSnapshot } from "./demo-snapshot.js";
import { serializeJson } from "./model.js";
import {
  buildSnapshotSummary,
  exportEvidenceBundle,
  findEpoch,
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

type CommandName =
  | "init-demo"
  | "summary"
  | "list"
  | "inspect"
  | "export-evidence"
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
  summary          Summarize a saved snapshot
  list             List issuer, verifier, recognition, or epoch records
  inspect          Print a specific snapshot record as JSON
  export-evidence  Export an anchored evidence bundle as JSON

Examples:
  trust-registry init-demo --output ./artifacts/trust-registry/demo.json
  trust-registry summary --snapshot ./artifacts/trust-registry/demo.json
  trust-registry list --snapshot ./artifacts/trust-registry/demo.json --kind issuer
  trust-registry inspect --snapshot ./artifacts/trust-registry/demo.json --kind epoch
  trust-registry export-evidence --snapshot ./artifacts/trust-registry/demo.json --kind issuer --id auth:issuer:passport:v1
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

const requireStringOption = (
  value: string | boolean | undefined,
  flag: string,
): string => {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${flag} is required`);
  }

  return value;
};

const isHelpRequest = (value: string | undefined): boolean =>
  value === undefined || value === "help" || value === "--help" || value === "-h";

const writeJson = (io: CliIo, value: unknown): void => {
  io.stdout(serializeJson(value));
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

const runSummary = async (argv: readonly string[], io: CliIo): Promise<number> => {
  const parsed = parseArgs({
    args: [...argv],
    allowPositionals: false,
    options: {
      snapshot: { type: "string" },
      json: { type: "boolean" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotFromFile(
    requireStringOption(parsed.values.snapshot, "--snapshot"),
  );
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
      kind: { type: "string" },
      json: { type: "boolean" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotFromFile(
    requireStringOption(parsed.values.snapshot, "--snapshot"),
  );
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
      kind: { type: "string" },
      id: { type: "string" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotFromFile(
    requireStringOption(parsed.values.snapshot, "--snapshot"),
  );
  const kind = parseKind(
    typeof parsed.values.kind === "string" ? parsed.values.kind : undefined,
  );
  const id = typeof parsed.values.id === "string" ? parsed.values.id : undefined;

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
      kind: { type: "string" },
      id: { type: "string" },
      output: { type: "string" },
    },
    strict: true,
  });
  const snapshot = await loadSnapshotFromFile(
    requireStringOption(parsed.values.snapshot, "--snapshot"),
  );
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
      case "summary":
        return await runSummary(rest, io);
      case "list":
        return await runList(rest, io);
      case "inspect":
        return await runInspect(rest, io);
      case "export-evidence":
        return await runExportEvidence(rest, io);
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
