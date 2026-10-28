import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdtemp, mkdir, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assessStandaloneObservationBinding, attachStandaloneAcceptanceEvidence, checkStandaloneAcceptanceEvidence,
  decideStandaloneAcceptanceCase, recordEvidenceFileIdentity } from "./check-standalone-acceptance-evidence.mjs";
import { assessStandaloneCaseDecisionChain } from "./standalone-acceptance-decision-policy.mjs";
import { API_RESTART_SCOPE, CURRENT_QUERY_SCOPE } from "./standalone-qualification-scope-policy.mjs";

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

test("acceptance inventory rejects placeholder candidate identities", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-identities-"));
  const script = fileURLToPath(new URL("./check-standalone-acceptance-evidence.mjs", import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  try {
    for (const [field, value] of [
      ["sourceRevision", "0".repeat(40)],
      ["installInventorySha256", "0".repeat(64)],
      ["signedPlanSha256", "0".repeat(64)],
      ["genesisHash", `0x${"0".repeat(64)}`],
      ["contractAddress", `0x${"0".repeat(64)}`],
    ]) {
      const candidate = { ...manifest(), [field]: value };
      await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /must pin one source/u);
      const result = run("init", root, candidate.sourceRevision, candidate.installInventorySha256,
        candidate.signedPlanSha256, candidate.genesisHash, candidate.contractAddress);
      assert.equal(result.status, 1, `${field} accepted by CLI`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("strict decision policy requires an ordered, current, source-bound verdict", () => {
  const raw = { path: "L01/receipt.log", sha256: "a".repeat(64) };
  const first = { path: "decisions/L01-first.json", sha256: "b".repeat(64) };
  const second = { path: "decisions/L01-second.json", sha256: "c".repeat(64) };
  const record = (previousStatus, status, evidence) => ({
    format: "tr-standalone-case-decision-v1", sourceRevision: "a".repeat(40),
    caseId: "L01", previousStatus, status, reviewer: "operator:test",
    reasonCode: "reviewed-receipt", decidedAt: "2026-10-27T00:00:00.000Z", evidence,
    reviewerAuthenticated: false, evidenceContentVerified: false, releaseQualified: false,
  });
  const evidence = [raw, first, second];
  const decisions = [
    { index: 1, path: first.path, record: record("not-run", "fail", [raw]) },
    { index: 2, path: second.path, record: record("fail", "pass", [raw, first]) },
  ];
  const assess = (status, entries = evidence, history = decisions) =>
    assessStandaloneCaseDecisionChain("L01", "a".repeat(40), status, entries, history);
  assert.equal(assess("pass"), true);
  assert.equal(assess("pass", [...evidence, { path: "L01/late.log", sha256: "d".repeat(64) }]), false);
  assert.equal(assess("pass", [raw], []), false);
  assert.throws(() => assess("fail"), /status differs/u);
  assert.throws(() => assess("pass", evidence, [decisions[1], decisions[0]]), /case history/u);
  assert.throws(() => assess("pass", evidence, [decisions[0], {
    ...decisions[1], record: { ...decisions[1].record, previousStatus: "not-run" },
  }]), /case history/u);
  for (const invalid of [
    { ...decisions[0].record, sourceRevision: "f".repeat(40) },
    { ...decisions[0].record, reviewerAuthenticated: true },
    { ...decisions[0].record, evidence: [] },
    { ...decisions[0].record, reviewer: "x" },
    { ...decisions[0].record, reasonCode: "Private details" },
    { ...decisions[0].record, decidedAt: "yesterday" },
    { ...decisions[0].record, decidedAt: "2026-10-27T01:00:00+01:00" },
    { ...decisions[0].record, extra: true },
  ]) {
    assert.throws(() => assess("pass", evidence, [{ ...decisions[0], record: invalid }, decisions[1]]),
      /case history/u);
  }
  assert.throws(() => assess("pass", evidence, [decisions[0], {
    ...decisions[1], record: { ...decisions[1].record, decidedAt: "2026-10-26T23:59:59.999Z" },
  }]), /case history/u);
});
const observation = (candidate) => ({
  format: "tr-standalone-qualification-observation-v1",
  sourceRevision: candidate.sourceRevision,
  inventorySha256: candidate.installInventorySha256,
  recordedVerifierKeyCatalog: "bundle-and-wizard-records-match-not-independent-finality",
  prerequisites: {
    format: "tr-standalone-journey-prerequisites-v1",
    sourceRevision: candidate.sourceRevision,
    expectedSourceRevision: candidate.sourceRevision,
    ledgerPrerequisitesObserved: true,
    missing: [],
    releaseQualified: false,
  },
  currentQuery: {
    format: "tr-standalone-current-query-journey-v2",
    sourceRevision: candidate.sourceRevision,
    installInventorySha256: candidate.installInventorySha256,
    networkId: "f".repeat(64),
    apiContainerId: "1".repeat(64),
    planSha256: candidate.signedPlanSha256,
    planExpectedGenesisHash: candidate.genesisHash,
    planContractAddress: candidate.contractAddress,
    selectedStateSha256: "2".repeat(64),
    registryId: "test-registry",
    currentEpochId: "test-epoch",
    finalizedCheckpoints: [`0x${"3".repeat(64)}`, `0x${"4".repeat(64)}`],
    counts: { issuer: 1, verifier: 1, auditor: 1, recognition: 1 },
    resolvedLookups: { issuer: 1, verifier: 1, auditor: 1, recognition: 1 },
    ambiguousLookups: { issuer: 0, verifier: 0, auditor: 0 },
    apiEgressCanaryDenied: true,
    apiDnsCanaryDenied: true,
    scope: CURRENT_QUERY_SCOPE,
    actorJourneys: "not-run",
    hostAndBrowserEgress: "not-verified",
    independentFinality: "not-verified",
    planToDeploymentBinding: "not-verified",
    releaseQualified: false,
  },
  apiRestart: "not-run",
  governedActorJourneys: "not-run",
  independentFinality: "not-verified",
  fullEgressDenial: "not-verified",
  deployedRecovery: "not-run",
  independentSecurityReview: "not-verified",
  releaseQualified: false,
});

test("read-only observation binds to one acceptance candidate without passing cases", () => {
  const candidate = manifest();
  const observed = observation(candidate);
  const result = assessStandaloneObservationBinding(candidate, observed);
  assert.equal(result.readOnlyObservationBound, true);
  assert.equal(result.actorJourney, "not-run");
  assert.equal(result.acceptanceCasesChanged, false);
  assert.equal(result.releaseQualified, false);
  assert.equal(candidate.cases.A04.status, "not-run");

  for (const change of [
    { sourceRevision: "9".repeat(40) },
    { inventorySha256: "9".repeat(64) },
    { recordedVerifierKeyCatalog: "verified" },
    { recordedVerifierKeyCatalog: undefined },
    { governedActorJourneys: "pass" },
    { releaseQualified: true },
  ]) {
    assert.throws(() => assessStandaloneObservationBinding(candidate, { ...observed, ...change }), /differs/u);
  }
  for (const change of [
    { installInventorySha256: "9".repeat(64) },
    { planSha256: "9".repeat(64) },
    { planExpectedGenesisHash: `0x${"9".repeat(64)}` },
    { planContractAddress: `0x${"9".repeat(64)}` },
    { apiEgressCanaryDenied: false },
    { apiDnsCanaryDenied: false },
    { actorJourneys: "pass" },
    { hostAndBrowserEgress: "verified" },
    { independentFinality: "verified" },
    { planToDeploymentBinding: "verified" },
    { ambiguousLookups: undefined },
    { ambiguousLookups: { issuer: 0, verifier: 2, auditor: 0 } },
    { resolvedLookups: { issuer: 2, verifier: 1, auditor: 1, recognition: 1 } },
  ]) {
    assert.throws(() => assessStandaloneObservationBinding(candidate,
      { ...observed, currentQuery: { ...observed.currentQuery, ...change } }), /differs/u);
  }
  const restart = {
    format: "tr-standalone-api-restart-observation-v1",
    sourceRevision: candidate.sourceRevision,
    installInventorySha256: candidate.installInventorySha256,
    networkId: observed.currentQuery.networkId,
    apiContainerId: observed.currentQuery.apiContainerId,
    planSha256: candidate.signedPlanSha256,
    selectedStateSha256: observed.currentQuery.selectedStateSha256,
    apiEgressCanaryDenied: true,
    apiDnsCanaryDenied: true,
    scope: API_RESTART_SCOPE,
    releaseQualified: false,
  };
  assert.equal(assessStandaloneObservationBinding(candidate,
    { ...observed, apiRestart: restart }).apiRestartBound, true);
  assert.throws(() => assessStandaloneObservationBinding(candidate,
    { ...observed, apiRestart: { ...restart, networkId: "0".repeat(64) } }), /differs/u);
  assert.throws(() => assessStandaloneObservationBinding(candidate,
    { ...observed, apiRestart: { ...restart, installInventorySha256: "9".repeat(64) } }), /differs/u);
  assert.throws(() => assessStandaloneObservationBinding(candidate,
    { ...observed, apiRestart: { ...restart, apiDnsCanaryDenied: false } }), /differs/u);
  assert.throws(() => assessStandaloneObservationBinding(candidate,
    { ...observed, currentQuery: { ...observed.currentQuery,
      governedActorJourneys: "passed" } }), /differs/u);
  assert.throws(() => assessStandaloneObservationBinding(candidate,
    { ...observed, apiRestart: { ...restart, independentFinality: "verified" } }), /differs/u);
  const pending = { ...observed, prerequisites: { ...observed.prerequisites,
    ledgerPrerequisitesObserved: false, missing: ["deploymentObserved"] }, currentQuery: "not-run",
    recordedVerifierKeyCatalog: "not-verified" };
  assert.equal(assessStandaloneObservationBinding(candidate, pending).readOnlyObservationBound, false);
  assert.throws(() => assessStandaloneObservationBinding(candidate,
    { ...pending, recordedVerifierKeyCatalog: observed.recordedVerifierKeyCatalog }),
  /inconsistent pending prerequisites/u);
});

test("observation CLI rejects public, linked, and mismatched evidence without changing verdicts", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-observe-"));
  const script = fileURLToPath(new URL("./check-standalone-acceptance-evidence.mjs", import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  try {
    const candidate = manifest();
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    const path = join(root, "observation.json");
    await writeFile(path, `${JSON.stringify(observation(candidate))}\n`, { mode: 0o600 });
    const matched = run("observe", root, candidate.sourceRevision, "observation.json");
    assert.equal(matched.status, 0, matched.stderr);
    assert.equal(JSON.parse(matched.stdout).readOnlyObservationBound, true);
    assert.deepEqual(JSON.parse(await readFile(join(root, "acceptance.json"), "utf8")), candidate);
    const pending = observation(candidate);
    pending.prerequisites.ledgerPrerequisitesObserved = false;
    pending.prerequisites.missing = ["deploymentObserved"];
    pending.currentQuery = "not-run";
    pending.recordedVerifierKeyCatalog = "not-verified";
    await writeFile(path, `${JSON.stringify(pending)}\n`, { mode: 0o600 });
    const blocked = run("observe", root, candidate.sourceRevision, "observation.json");
    assert.equal(blocked.status, 2, blocked.stderr);
    assert.equal(JSON.parse(blocked.stdout).readOnlyObservationBound, false);
    await writeFile(path, `${JSON.stringify(observation(candidate))}\n`, { mode: 0o600 });
    assert.equal(run("observe", root, "9".repeat(40), "observation.json").status, 1);
    await writeFile(path, `${JSON.stringify(observation({ ...candidate,
      signedPlanSha256: "9".repeat(64) }))}\n`, { mode: 0o600 });
    assert.equal(run("observe", root, candidate.sourceRevision, "observation.json").status, 1);
    await symlink("observation.json", join(root, "linked.json"));
    assert.equal(run("observe", root, candidate.sourceRevision, "linked.json").status, 1);
    await writeFile(join(root, "public.json"), "{}\n", { mode: 0o644 });
    assert.equal(run("observe", root, candidate.sourceRevision, "public.json").status, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("inventory is fail-closed and never asserts release qualification", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-"));
  try {
    const candidate = manifest();
    const pending = await checkStandaloneAcceptanceEvidence(root, candidate);
    assert.equal(pending.completeInventory, false);
    assert.deepEqual(pending.notRunCases, CASES);
    assert.equal(pending.allOperatorCasesPassed, false);
    assert.equal(pending.releaseQualified, false);
    assert.equal(pending.receiptAndFinalityContent, "not-independently-verified");
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate, "f".repeat(40)),
      /differs from the selected candidate/u);
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate, "not-a-sha"),
      /full lowercase commit SHA/u);
    for (const id of CASES) {
      const bytes = Buffer.from(`raw operator output for ${id}\n`);
      await writeFile(join(root, `${id}.log`), bytes, { mode: 0o600 });
      candidate.cases[id] = { status: "pass", evidence: [{ path: `${id}.log`, sha256: sha(bytes) }] };
    }
    assert.equal((await checkStandaloneAcceptanceEvidence(root, candidate)).completeInventory, false);
    for (const id of CASES) candidate.cases[id].status = "not-run";
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    for (const id of CASES) {
      await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, id, "pass",
        "operator:test", "reviewed-raw-evidence");
    }
    const decided = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    const complete = await checkStandaloneAcceptanceEvidence(root, decided);
    assert.equal(complete.completeInventory, true);
    assert.deepEqual(complete.operatorPassedCases, CASES);
    assert.deepEqual(complete.operatorFailedCases, []);
    assert.deepEqual(complete.notRunCases, []);
    assert.equal(complete.allOperatorCasesPassed, true);
    assert.equal(Object.values(complete.decisionBackedCases).every(Boolean), true);
    assert.equal(complete.releaseQualified, false);
    await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "L01", "fail",
      "operator:test", "readback-disputed");
    const failed = await checkStandaloneAcceptanceEvidence(root,
      JSON.parse(await readFile(join(root, "acceptance.json"), "utf8")));
    assert.equal(failed.completeInventory, false);
    assert.deepEqual(failed.operatorFailedCases, ["L01"]);
    assert.equal(failed.allOperatorCasesPassed, false);
    await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "L01", "not-run",
      "operator:test", "rerun-required");
    const notRun = await checkStandaloneAcceptanceEvidence(root,
      JSON.parse(await readFile(join(root, "acceptance.json"), "utf8")));
    assert.equal(notRun.completeInventory, false);
    assert.deepEqual(notRun.notRunCases, ["L01"]);
    assert.equal(notRun.allOperatorCasesPassed, false);
    await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "L01", "pass",
      "operator:test", "rerun-reviewed");
    await writeFile(join(root, "late.log"), "late evidence\n", { mode: 0o600 });
    await attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision, "L01", "late.log");
    const stale = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    assert.equal((await checkStandaloneAcceptanceEvidence(root, stale)).completeInventory, false);
    await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "L01", "pass",
      "operator:test", "reviewed-late-evidence");
    await writeFile(join(root, "L01.log"), "modified\n");
    const changed = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, changed), /SHA-256 mismatch/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("inventory rejects a status edit or reordered evidence after an operator decision", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-decision-chain-"));
  try {
    const candidate = manifest();
    const bytes = Buffer.from("first receipt\n");
    await writeFile(join(root, "first.log"), bytes, { mode: 0o600 });
    candidate.cases.L01.evidence.push({ path: "first.log", sha256: sha(bytes) });
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "L01", "pass",
      "operator:test", "reviewed-first-receipt");
    const decided = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    decided.cases.L01.status = "fail";
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, decided), /status differs/u);
    decided.cases.L01.status = "pass";
    decided.cases.L01.evidence.reverse();
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, decided), /decision does not match/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an older manually labeled case needs a fresh decision before it counts", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-first-decision-"));
  try {
    const candidate = manifest();
    const bytes = Buffer.from("legacy receipt\n");
    await writeFile(join(root, "legacy.log"), bytes, { mode: 0o600 });
    candidate.cases.L01 = { status: "pass", evidence: [{ path: "legacy.log", sha256: sha(bytes) }] };
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    const before = await checkStandaloneAcceptanceEvidence(root, candidate);
    assert.equal(before.decisionBackedCases.L01, false);
    const decision = await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "L01",
      "pass", "operator:test", "reviewed-legacy-receipt");
    assert.equal(decision.previousStatus, "pass");
    const updated = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    const after = await checkStandaloneAcceptanceEvidence(root, updated);
    assert.equal(after.decisionBackedCases.L01, true);
    assert.equal(after.completeInventory, false);
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
    await writeFile(join(root, "receipt.log"), bytes, { mode: 0o600 });
    candidate.cases.S01 = { status: "pass", evidence: [{ path: "receipt.log", sha256: sha(bytes) }] };
    candidate.cases.L01 = { status: "pass", evidence: [{ path: "receipt.log", sha256: sha(bytes) }] };
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /reused/u);
    await writeFile(join(root, "RECEIPT.LOG"), bytes, { mode: 0o600 });
    candidate.cases.L01.evidence[0].path = "RECEIPT.LOG";
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /reused/u);
    await writeFile(join(root, "\u00e9.log"), bytes, { mode: 0o600 });
    await writeFile(join(root, "e\u0301.log"), bytes, { mode: 0o600 });
    candidate.cases.S01.evidence[0].path = "\u00e9.log";
    candidate.cases.L01.evidence[0].path = "e\u0301.log";
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
    await mkdir(join(root, "L01"), { mode: 0o700 });
    await writeFile(join(root, "L01/deploy.log"), "operator raw receipt\n", { mode: 0o600 });
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
    await writeFile(join(root, "L01/public.log"), "public receipt\n", { mode: 0o644 });
    await chmod(join(root, "L01/public.log"), 0o644);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "L01/public.log"), /private nonempty bounded regular file/u);
    await mkdir(join(root, "public-parent"), { mode: 0o755 });
    await chmod(join(root, "public-parent"), 0o755);
    await writeFile(join(root, "public-parent/receipt.log"), "private file\n", { mode: 0o600 });
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "public-parent/receipt.log"), /private real directory/u);
    await chmod(join(root, "L01/deploy.log"), 0o644);
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, updated),
      /private nonempty bounded regular file/u);
    await chmod(join(root, "L01/deploy.log"), 0o600);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "L01/deploy.log"), /already attached/u);
    await writeFile(join(root, "L01/DEPLOY.LOG"), "operator raw receipt\n", { mode: 0o600 });
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "L01/DEPLOY.LOG"), /reused/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, "f".repeat(40),
      "A01", "L01/deploy.log"), /differs from the selected candidate/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "../outside.log"), /relative path/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "acceptance.json"), /cannot be attached as its own evidence/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "ACCEPTANCE.JSON"), /cannot be attached as its own evidence/u);
    assert.deepEqual(JSON.parse(await readFile(join(root, "acceptance.json"), "utf8")), updated);
    const selfReferential = structuredClone(updated);
    selfReferential.cases.A01.evidence = [{ path: "acceptance.json", sha256: sha(await readFile(join(root, "acceptance.json"))) }];
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, selfReferential),
      /cannot be attached as its own evidence/u);
    selfReferential.cases.A01.evidence[0].path = "ACCEPTANCE.JSON";
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, selfReferential),
      /cannot be attached as its own evidence/u);
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

test("operator verdicts require raw evidence and leave a private hash-linked record", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-decision-"));
  const script = fileURLToPath(new URL("./check-standalone-acceptance-evidence.mjs", import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  try {
    const candidate = manifest();
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    assert.equal(run("decide", root, candidate.sourceRevision, "A01", "pass",
      "operator:alice", "finalized-readback-reviewed").status, 1);
    assert.equal(run("decide", root, "f".repeat(40), "A01", "not-run",
      "operator:alice", "not-started").status, 1);
    await writeFile(join(root, "actor.log"), "redacted actor receipt\n", { mode: 0o600 });
    await attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision, "A01", "actor.log");
    const passed = run("decide", root, candidate.sourceRevision, "A01", "pass",
      "operator:alice", "finalized-readback-reviewed");
    assert.equal(passed.status, 0, passed.stderr);
    const first = JSON.parse(passed.stdout);
    assert.equal(first.status, "pass");
    assert.equal(first.previousStatus, "not-run");
    assert.equal(first.reviewerAuthenticated, false);
    assert.equal(first.releaseQualified, false);
    const firstRecord = JSON.parse(await readFile(join(root, first.decisionPath), "utf8"));
    assert.deepEqual(firstRecord.evidence, [{ path: "actor.log", sha256: sha("redacted actor receipt\n") }]);
    assert.equal(firstRecord.evidenceContentVerified, false);
    assert.equal((await lstat(join(root, first.decisionPath))).mode & 0o777, 0o600);
    assert.equal((await lstat(join(root, "decisions"))).mode & 0o777, 0o700);
    const failed = await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "A01", "fail",
      "operator:bob", "receipt-disputed");
    assert.equal(failed.previousStatus, "pass");
    const secondRecord = JSON.parse(await readFile(join(root, failed.decisionPath), "utf8"));
    assert.equal(secondRecord.previousStatus, "pass");
    assert.equal(secondRecord.evidence.length, 2);
    const updated = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    assert.equal(updated.cases.A01.status, "fail");
    assert.equal(updated.cases.A01.evidence.length, 3);
    assert.equal((await checkStandaloneAcceptanceEvidence(root, updated)).releaseQualified, false);
    await mkdir(join(root, ".acceptance.lock"));
    await assert.rejects(decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "A01", "pass",
      "operator:alice", "recheck-complete"), { code: "EEXIST" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("raw evidence capacity does not prevent a later verdict reversal", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-capacity-"));
  try {
    const candidate = manifest();
    for (let index = 0; index < 31; index += 1) {
      const path = `raw-${index}.log`;
      const bytes = `receipt ${index}\n`;
      await writeFile(join(root, path), bytes, { mode: 0o600 });
      candidate.cases.A01.evidence.push({ path, sha256: sha(bytes) });
    }
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "A01", "pass",
      "operator:alice", "initial-review");
    await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "A01", "fail",
      "operator:alice", "receipt-disputed");
    await writeFile(join(root, "raw-31.log"), "additional receipt\n", { mode: 0o600 });
    await attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision, "A01", "raw-31.log");
    await writeFile(join(root, "raw-32.log"), "excess receipt\n", { mode: 0o600 });
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "raw-32.log"), /raw evidence limit/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "decisions/forged.json"), /reserved/u);
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "Decisions/forged.json"), /reserved/u);
    const updated = JSON.parse(await readFile(join(root, "acceptance.json"), "utf8"));
    assert.equal(updated.cases.A01.status, "fail");
    assert.equal(updated.cases.A01.evidence.length, 34);
    assert.equal((await checkStandaloneAcceptanceEvidence(root, updated)).releaseQualified, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects Unicode aliases that resolve to one evidence file", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-unicode-alias-"));
  try {
    const bytes = "operator receipt\n";
    await writeFile(join(root, "\u03c3.log"), bytes, { mode: 0o600 });
    const alias = await lstat(join(root, "\u03c2.log")).catch(() => null);
    const original = await lstat(join(root, "\u03c3.log"));
    if (!alias || alias.dev !== original.dev || alias.ino !== original.ino) {
      t.skip("filesystem does not fold Greek sigma and final sigma to one file");
      return;
    }
    const candidate = manifest();
    candidate.cases.L01.evidence = [{ path: "\u03c3.log", sha256: sha(bytes) }];
    candidate.cases.S01.evidence = [{ path: "\u03c2.log", sha256: sha(bytes) }];
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /reused/u);
    candidate.cases.S01.evidence = [];
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "S01", "\u03c2.log"), /reused/u);
    assert.deepEqual(JSON.parse(await readFile(join(root, "acceptance.json"), "utf8")), candidate);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a hard-linked decision cannot be attached as raw case evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-link-"));
  try {
    const candidate = manifest();
    await writeFile(join(root, "acceptance.json"), `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    const decision = await decideStandaloneAcceptanceCase(root, candidate.sourceRevision, "L01", "not-run",
      "operator:alice", "not-started");
    await link(join(root, decision.decisionPath), join(root, "copied-decision.json"));
    await assert.rejects(attachStandaloneAcceptanceEvidence(root, candidate.sourceRevision,
      "A01", "copied-decision.json"), /bounded regular file/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("validator rejects decision-only passes and unreadable oversized manifests", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-bounds-"));
  try {
    const candidate = manifest();
    candidate.cases.A01 = { status: "pass", evidence: [{
      path: "decisions/A01-fake.json", sha256: "f".repeat(64),
    }] };
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /raw evidence for pass/u);
    candidate.cases.A01.status = "not-run";
    candidate.cases.A01.evidence = [{ path: `receipt-${"x".repeat(1024 * 1024)}.log`,
      sha256: "f".repeat(64) }];
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /readable size limit/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects hard-link aliases of one evidence file", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-acceptance-hardlink-alias-"));
  try {
    const bytes = "operator receipt\n";
    await writeFile(join(root, "first.log"), bytes, { mode: 0o600 });
    await link(join(root, "first.log"), join(root, "second.log"));
    const candidate = manifest();
    candidate.cases.L01.evidence = [{ path: "first.log", sha256: sha(bytes) }];
    candidate.cases.S01.evidence = [{ path: "second.log", sha256: sha(bytes) }];
    await assert.rejects(checkStandaloneAcceptanceEvidence(root, candidate), /bounded regular file/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("file identity guard rejects reused inode independent of filesystem aliasing", () => {
  const seen = new Set();
  recordEvidenceFileIdentity(seen, "1:42", "first.log");
  assert.throws(() => recordEvidenceFileIdentity(seen, "1:42", "second.log"), /reused/u);
  recordEvidenceFileIdentity(seen, "1:43", "third.log");
  assert.deepEqual([...seen], ["1:42", "1:43"]);
});
