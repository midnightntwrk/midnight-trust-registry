import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { checkStandaloneSecurityVerdict } from "./check-standalone-security-verdict.mjs";
import { ACCEPTANCE_CASES } from "./standalone-acceptance-manifest-policy.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const fingerprint = "A".repeat(40);
const sourceRevision = "b".repeat(40);
const findings = "# Independent review findings\n\nNo findings in this test fixture.\n";
const base = {
  format: "tr-standalone-acceptance-evidence-v1",
  sourceRevision,
  installInventorySha256: "c".repeat(64),
  signedPlanSha256: "d".repeat(64),
  genesisHash: `0x${"e".repeat(64)}`,
  contractAddress: `0x${"f".repeat(64)}`,
};
const verdict = {
  format: "tr-local-security-verdict-v2",
  sourceRevision,
  installInventorySha256: base.installInventorySha256,
  signedPlanSha256: base.signedPlanSha256,
  genesisHash: base.genesisHash,
  contractAddress: base.contractAddress,
  reviewerFingerprint: fingerprint,
  reviewedAt: "2026-10-28T10:00:00.000Z",
  scope: "self-hosted-local-0.1.0",
  findingsPath: "findings.md",
  findingsSha256: sha(findings),
  outcome: "approve",
};

test("signed S01 verdict is bound to raw attachments and exact candidate without qualifying release", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-security-verdict-"));
  try {
    const document = `${JSON.stringify(verdict, null, 2)}\n`;
    const signature = "test-detached-signature\n";
    const manifest = {
      ...base,
      cases: Object.fromEntries(ACCEPTANCE_CASES.map((id) => [id, { status: "not-run", evidence: [] }])),
    };
    const write = (name, bytes) => writeFile(join(root, name), bytes, { mode: 0o600 });
    await write("verdict.json", document);
    await write("verdict.sig", signature);
    await write("findings.md", findings);
    manifest.cases.S01.evidence = [
      { path: "verdict.json", sha256: sha(document) },
      { path: "verdict.sig", sha256: sha(signature) },
      { path: "findings.md", sha256: sha(findings) },
    ];
    await write("acceptance.json", `${JSON.stringify(manifest)}\n`);
    const calls = [];
    const verify = async (...args) => { calls.push(args); };
    const check = (doc = "verdict.json", sig = "verdict.sig", key = fingerprint) =>
      checkStandaloneSecurityVerdict(root, sourceRevision, doc, sig, "/trusted/reviewer.asc", key, verify);
    const report = await check();
    assert.equal(report.signatureValidForPinnedKey, true);
    assert.equal(report.outcome, "approve");
    assert.equal(report.reviewerIndependence, "not-verified");
    assert.equal(report.findingsDigestBound, true);
    assert.equal(report.releaseQualified, false);
    assert.deepEqual(calls[0], [Buffer.from(document), Buffer.from(signature),
      "/trusted/reviewer.asc", fingerprint, verdict.reviewedAt]);
    await assert.rejects(check("verdict.sig", "verdict.json"), /not valid JSON/u);
    await assert.rejects(check("verdict.json", "missing.sig"), /distinct flat raw S01 attachments/u);
    await assert.rejects(check("verdict.json", "verdict.sig", "B".repeat(40)),
      /selected standalone candidate/u);
    assert.equal(calls.length, 1);
    manifest.cases.S01.evidence.pop();
    await write("acceptance.json", `${JSON.stringify(manifest)}\n`);
    await assert.rejects(check(), /selected standalone candidate/u);
    manifest.cases.S01.evidence.push({ path: "findings.md", sha256: sha(findings) });
    await write("acceptance.json", `${JSON.stringify(manifest)}\n`);

    const stale = `${JSON.stringify({ ...verdict, contractAddress: `0x${"1".repeat(64)}` }, null, 2)}\n`;
    await write("verdict.json", stale);
    await assert.rejects(check(), /evidence SHA-256 mismatch/u);
    manifest.cases.S01.evidence[0].sha256 = sha(stale);
    await write("acceptance.json", `${JSON.stringify(manifest)}\n`);
    await assert.rejects(check(), /selected standalone candidate/u);
    const ambiguous = document.replace('"outcome": "approve"', '"outcome": "reject", "outcome": "approve"');
    await write("verdict.json", ambiguous);
    manifest.cases.S01.evidence[0].sha256 = sha(ambiguous);
    await write("acceptance.json", `${JSON.stringify(manifest)}\n`);
    await assert.rejects(check(), /canonical signed JSON without duplicate keys/u);
    await write("verdict.json", document);
    manifest.cases.S01.evidence[0].sha256 = sha(document);
    await write("findings.md", `${findings}Substituted finding.\n`);
    manifest.cases.S01.evidence[2].sha256 = sha(`${findings}Substituted finding.\n`);
    await write("acceptance.json", `${JSON.stringify(manifest)}\n`);
    await assert.rejects(check(), /Signed security findings digest differs/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the signature verifier failure is not converted into a security approval", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-security-verdict-failure-"));
  try {
    const document = `${JSON.stringify(verdict, null, 2)}\n`;
    const signature = "invalid\n";
    const cases = Object.fromEntries(ACCEPTANCE_CASES.map((id) => [id, { status: "not-run", evidence: [] }]));
    cases.S01.evidence = [
      { path: "verdict.json", sha256: sha(document) },
      { path: "verdict.sig", sha256: sha(signature) },
      { path: "findings.md", sha256: sha(findings) },
    ];
    await writeFile(join(root, "verdict.json"), document, { mode: 0o600 });
    await writeFile(join(root, "verdict.sig"), signature, { mode: 0o600 });
    await writeFile(join(root, "findings.md"), findings, { mode: 0o600 });
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify({ ...base, cases })}\n`, { mode: 0o600 });
    await assert.rejects(checkStandaloneSecurityVerdict(root, sourceRevision, "verdict.json",
      "verdict.sig", "/trusted/reviewer.asc", fingerprint,
      async () => { throw new Error("signature invalid"); }), /signature invalid/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI verifies a real detached GPG verdict and rejects substitution", async (t) => {
  assert.equal(spawnSync("gpg", ["--version"], { stdio: "ignore" }).status, 0,
    "GPG is required for signed security-review verification");
  const root = await mkdtemp("/tmp/tr-sv-gpg-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const signer = join(root, "signer");
  await mkdir(signer, { mode: 0o700 });
  execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
    "--passphrase", "", "--quick-generate-key", "Security Reviewer <reviewer@example.test>",
    "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
  const listing = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
    "--list-secret-keys"], { encoding: "utf8" });
  const key = listing.split("\n").find((line) => line.startsWith("fpr:"))?.split(":")[9];
  assert.match(key, /^[A-F0-9]{40}$/u);
  const publicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--armor",
    "--export", key]);
  await writeFile(join(root, "reviewer.asc"), publicKey, { mode: 0o600 });
  await writeFile(join(root, "findings.md"), findings, { mode: 0o600 });
  const candidate = { ...base, cases: Object.fromEntries(ACCEPTANCE_CASES.map((id) =>
    [id, { status: "not-run", evidence: [] }])) };
  const signed = { ...verdict, reviewerFingerprint: key,
    reviewedAt: new Date(Date.now() - 60_000).toISOString() };
  const writeCandidate = async (outcome) => {
    const document = `${JSON.stringify({ ...signed, outcome }, null, 2)}\n`;
    await writeFile(join(root, "verdict.json"), document, { mode: 0o600 });
    candidate.cases.S01.evidence = [
      { path: "verdict.json", sha256: sha(document) },
      { path: "verdict.sig", sha256: sha(await readFile(join(root, "verdict.sig"))) },
      { path: "findings.md", sha256: sha(await readFile(join(root, "findings.md"))) },
    ];
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
  };
  const sign = async () => {
    execFileSync("gpg", ["--homedir", signer, "--batch", "--yes",
      "--detach-sign", "--output", join(root, "verdict.sig"), join(root, "verdict.json")],
    { stdio: "pipe", timeout: 30_000 });
    await chmod(join(root, "verdict.sig"), 0o600);
  };
  const script = fileURLToPath(new URL("./check-standalone-security-verdict.mjs", import.meta.url));
  const run = (expected = key) => spawnSync(process.execPath, [script, root, sourceRevision,
    "verdict.json", join(root, "reviewer.asc"), "verdict.sig", expected], { encoding: "utf8" });
  await writeFile(join(root, "verdict.json"), `${JSON.stringify(signed, null, 2)}\n`, { mode: 0o600 });
  await sign();
  await writeCandidate("approve");
  const approved = run();
  assert.equal(approved.status, 0, approved.stderr);
  assert.equal(JSON.parse(approved.stdout).releaseQualified, false);
  assert.equal(JSON.parse(approved.stdout).findingsDigestBound, true);
  assert.equal(run("B".repeat(40)).status, 1);

  await writeFile(join(root, "findings.md"), `${findings}Substituted finding.\n`, { mode: 0o600 });
  await writeCandidate("approve");
  assert.equal(run().status, 1, "a changed findings report must fail even after the inventory hash is updated");
  await writeFile(join(root, "findings.md"), findings, { mode: 0o600 });

  await writeCandidate("reject");
  const tampered = run();
  assert.equal(tampered.status, 1, "changed verdict must fail even when manifest hash is updated");
  await sign();
  await writeCandidate("reject");
  const rejected = run();
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stdout).outcome, "reject");
});
