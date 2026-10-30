import { fork } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const childPath = fileURLToPath(new URL("./fixtures/proposal-journal-process.mjs", import.meta.url));

async function child(path: string, operation: string): Promise<string[]> {
  const process = fork(childPath, [path, operation], {
    execArgv: [], stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
  const messages: string[] = [];
  let diagnostic = "";
  process.stderr?.on("data", (chunk: Buffer) => { diagnostic += chunk.toString(); });
  try {
    await new Promise<void>((resolveChild, rejectChild) => {
      const timer = setTimeout(() => {
        process.kill();
        rejectChild(new Error(`Journal child timed out: ${diagnostic}`));
      }, 15_000);
      process.on("message", (message: unknown) => {
        if (typeof message === "string") messages.push(message);
      });
      process.once("error", (error) => { clearTimeout(timer); rejectChild(error); });
      process.once("exit", (code) => {
        clearTimeout(timer);
        if (code === 0) resolveChild();
        else rejectChild(new Error(`Journal child failed (${String(code)}): ${diagnostic}`));
      });
    });
  } finally {
    if (process.exitCode === null) process.kill();
  }
  expect(messages.at(-1)).toBe("complete");
  return messages.slice(0, -1);
}

describe("durable local proposal quarantine across fresh journal and provider callback processes", () => {
  let directory: string;
  let path: string;
  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "tr-proposal-process-"));
    path = join(directory, "journal.json");
  });
  afterEach(async () => { await rm(directory, { recursive: true, force: true }); });

  it("prevents a new provider process from reaching submission after an ambiguous response", async () => {
    expect(await child(path, "reserve")).toEqual(["provider-created", "submission-callback"]);
    const reserved = await readFile(path);
    expect(await child(path, "retry")).toEqual(["provider-created", "blocked"]);
    expect(await child(path, "other")).toEqual(["provider-created", "blocked"]);
    expect(await child(path, "lagging")).toEqual(["provider-created"]);
    expect(await child(path, "retry")).toEqual(["provider-created", "blocked"]);
    expect(await child(path, "other")).toEqual(["provider-created", "blocked"]);
    expect(await readFile(path)).toEqual(reserved);
    expect(await child(path, "observed")).toEqual(["provider-created"]);
    expect(await child(path, "retry")).toEqual(["provider-created", "blocked"]);
    expect(await child(path, "other")).toEqual(["provider-created", "submission-callback"]);
  }, 90_000);

  it("never calls the provider when reservation persistence fails", async () => {
    await writeFile(join(directory, "not-a-directory"), "blocked", { mode: 0o600 });
    expect(await child(join(directory, "not-a-directory", "journal.json"), "write-failure"))
      .toEqual(["provider-created", "blocked"]);
  });

  it("never calls the provider when a bound journal cannot persist the reservation", async () => {
    expect(await child(path, "reservation-write-failure")).toEqual(["provider-created", "blocked"]);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({ version: 1, attempts: [] });
    expect(await child(path, "other")).toEqual(["provider-created", "submission-callback"]);
  });
});
