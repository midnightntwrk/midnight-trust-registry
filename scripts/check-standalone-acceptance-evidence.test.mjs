import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { attachStandaloneAcceptanceEvidence, checkStandaloneAcceptanceEvidence } from "./check-standalone-acceptance-evidence.mjs";

const CASES = ["L01", "L02", "A01", "A02", "A03", "A04", "N01", "O01", "R01", "S01"];
const sha = (value) => createHash("sha256").update(value).digest("hex");
const manifest = () => ({
  format: "tr-standalone-acceptance-evidence-v1",
  sourceRevision: "a".repeat(40),
  installInventorySha256: "b".repeat(64),
  signedPlanSha256: "c".repeat(64),
  genesisHash: `0x${"d".repeat(64)}`,
  contractAddress: `0x${"e".repeat(64)}`,
  cases: Object.fromEntries(CASES.map((id) => [id, { status: "not-run", evidence: [] }])),
});

test("inventory is fail-closed and never asserts release qualification", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-"));
  try {
    const candidate = manifest();
    const pending = await checkStandaloneAcceptanceEvidence(root, candidate);
    assert.equal(pending.completeInventory, false);
    assert.equal(pending.releaseQualified, false);
    assert.equal(pending.receiptAndFinalityContent, "not-independently-verified");
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate, "f".repeat(40)),
      /differs from the selected candidate/u);
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate, "not-a-sha"),
      /full lowercase commit SHA/u);
    for (const id of CASES) {
      const bytes = Buffer.from(`raw operator output for ${id}\n`);
      await writeFile(join(root, `${id}.log`), bytes);
      candidate.cases[id] = { status: "pass", evidence: [{ path: `${id}.log`, sha256: sha(bytes) }] };
    }
    const complete = await checkStandaloneAcceptanceEvidence(root, candidate);
    assert.equal(complete.completeInventory, true);
    assert.equal(complete.releaseQualified, false);
    await writeFile(join(root, "L01.log"), "modified\n");
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /SHA-256 mismatch/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects missing cases, evidence reuse, traversal, symlinks and unbounded claims", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-"));
  try {
    const candidate = manifest();
    delete candidate.cases.S01;
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /all cases/u);
    candidate.cases.S01 = { status: "pass", evidence: [] };
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /S01 requires/u);
    const bytes = Buffer.from("evidence\n");
    await writeFile(join(root, "receipt.log"), bytes);
    candidate.cases.S01 = { status: "pass", evidence: [{ path: "receipt.log", sha256: sha(bytes) }] };
    candidate.cases.L01 = { status: "pass", evidence: [{ path: "receipt.log", sha256: sha(bytes) }] };
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /reused/u);
    candidate.cases.L01 = { status: "not-run", evidence: [] };
    candidate.cases.S01.evidence[0].path = "../receipt.log";
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /relative path/u);
    candidate.cases.S01.evidence[0].path = "linked.log";
    await symlink(join(root, "receipt.log"), join(root, "linked.log"));
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate));
    await mkdir(join(root, "nested"));
    await symlink(join(root, "nested"), join(root, "linked-dir"));
    candidate.cases.S01.evidence[0].path = "linked-dir/receipt.log";
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /real directory/u);
    candidate.cases.S01.status = "unknown";
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /S01 requires/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI initializes a private manifest, reports pending cases and rejects a linked manifest", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-cli-"));
  const script = fileURLToPath(new URL("./check-standalone-acceptance-evidence.mjs", import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  try {
    const candidate = manifest();
    const initialized = run("init", root, candidate.sourceRevision, candidate.installInventorySha256,
      candidate.signedPlanSha256, candidate.genesisHash, candidate.contractAddress);
    assert.equal(initialized.status, 0, initialized.stderr);
    assert.deepEqual(JSON.parse(await readFile(join(root, "acceptance.json"), "utf8")), candidate);
    assert.equal(run(root).status, 1);
    assert.equal(run(root, "f".repeat(40)).status, 1);
    assert.match(run(root, "f".repeat(40)).stderr, /differs from the selected candidate/u);
    assert.equal(run(root, candidate.sourceRevision).status, 2);
    assert.equal(run("init", root, candidate.sourceRevision, candidate.installInventorySha256,
      candidate.signedPlanSha256, candidate.genesisHash, candidate.contractAddress).status, 1);
    await rename(join(root, "acceptance.json"), join(root, "saved.json"));
    await symlink(join(root, "saved.json"), join(root, "acceptance.json"));
    assert.equal(run(root, candidate.sourceRevision).status, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attaches raw evidence without changing an operator verdict or claiming qualification", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-attach-"));
  const script = fileURLToPath(new URL("./check-standalone-acceptance-evidence.mjs", import.meta.url));
  try {
    const candidate = manifest();
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    await mkdir(join(root, "L01"));
    await writeFile(join(root, "L01/deploy.log"), "operator raw receipt\n");
    const result = spawnSync(process.execPath, [script, "attach", root, candidate.sourceRevision,
      "L01", "L01/deploy.log"], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "not-run");
    assert.equal(report.releaseQualified, false);
    const updated = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    assert.deepEqual(updated.cases.L01.evidence, [{ path: "L01/deploy.log", sha256: sha("operator raw receipt\n") }]);
    assert.equal(updated.cases.L01.status, "not-run");
    assert.equal((await checkStandaloneAcceptanceEvidence(root, updated)).completeInventory, false);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "L01/deploy.log"), /already attached/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, "f".repeat(40),
      "A01", "L01/deploy.log"), /differs from the selected candidate/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "../outside.log"), /relative path/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects an attached symlink and an active evidence writer lock", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-attach-"));
  try {
    const candidate = manifest();
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    await writeFile(join(root, "raw.log"), "private receipt\n");
    await symlink("raw.log", join(root, "linked.log"));
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "L01", "linked.log"));
    await mkdir(join(root, ".acceptance.lock"));
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "L01", "raw.log"), { code: "EEXIST" });
    assert.deepEqual(JSON.parse(await readFile(join(root, "acceptance.json"), "utf8")), candidate);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
