import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, mkdir, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";

import { prepareStandaloneGenesisReviewPacket, renderGenesisReviewPacket,
  validateGenesisReviewEvidence } from "./prepare-standalone-genesis-review.mjs";

const profile = getLocalNetworkProfile();
const revision = "a".repeat(40);
const inventorySha256 = "b".repeat(64);
const genesis = `0x${"c".repeat(64)}`;
const project = "tr-standalone-local-review-test";
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

function fixture(bundle) {
  const record = { sourceRevision: revision, networkProfile: profile,
    install: { bundle, inventorySha256 },
    stack: { project, state: "observed-ledger-bridge-only", observation: { observedAt: "now" } } };
  const candidate = { format: "tr-local-genesis-candidate-v1", sourceRevision: revision,
    installInventorySha256: inventorySha256, project, networkId: profile.networkId,
    nodeReportedGenesisHash: genesis, nodeReportedFinalizedBlockHash: `0x${"d".repeat(64)}`,
    nodeReportedFinalizedHeight: 7, observerSha256: "e".repeat(64),
    observedAt: "2026-10-26T20:00:00.000Z",
    status: "untrusted-node-observation-independent-review-required" };
  const pin = { format: "tr-local-ledger-pin-v1", networkId: profile.networkId,
    sourceRevision: revision, rpcUrl: "http://127.0.0.1:40947",
    expectedGenesisHash: genesis, allowedHosts: ["127.0.0.1"] };
  const verified = { sourceRevision: revision, inventorySha256,
    images: [{ role: "node", reference: `midnight/node@sha256:${"f".repeat(64)}` }] };
  return { record, candidate, pin, verified };
}

test("packet labels self-reported values and independent approval requirements", () => {
  const { record, candidate, pin, verified } = fixture("/private/bundle");
  const evidence = validateGenesisReviewEvidence(record, candidate, pin, verified);
  const packet = renderGenesisReviewPacket(evidence, "1".repeat(64), "2".repeat(64));
  assert.match(packet, /UNTRUSTED/u);
  assert.match(packet, /controlled independently of this running node/u);
  assert.match(packet, /\*\*not\*\* independent evidence/u);
  assert.match(packet, /Never sign this packet/u);
  assert.match(packet, /maintenance roster/u);
  for (const invalid of [
    { candidate: { ...candidate, installInventorySha256: "0".repeat(64) } },
    { candidate: { ...candidate, project: "tr-standalone-local-other" } },
    { pin: { ...pin, expectedGenesisHash: `0x${"0".repeat(64)}` } },
    { pin: { ...pin, rpcUrl: "http://example.com:40947" } },
    { record: { ...record, networkProfile: { ...profile, networkId: "preview" } } },
    { verified: { ...verified, inventorySha256: "0".repeat(64) } },
  ]) {
    assert.throws(() => validateGenesisReviewEvidence(
      invalid.record ?? record, invalid.candidate ?? candidate,
      invalid.pin ?? pin, invalid.verified ?? verified));
  }
});

test("packet uses private immutable inputs and never overwrites evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-genesis-review-"));
  const directory = join(root, "private");
  const bundle = join(root, "bundle");
  await mkdir(directory, { mode: 0o700 });
  await mkdir(bundle);
  const { record, candidate, pin, verified } = fixture(bundle);
  const candidateBytes = Buffer.from(JSON.stringify(candidate));
  const pinBytes = Buffer.from(JSON.stringify(pin));
  const candidatePath = join(directory, "genesis-candidate.untrusted.json");
  try {
    await writeFile(join(directory, "setup-record.json"), JSON.stringify(record), { mode: 0o600 });
    await writeFile(candidatePath, candidateBytes, { mode: 0o600 });
    await writeFile(join(directory, "genesis-pin.proposed.json"), pinBytes, { mode: 0o600 });
    const dependencies = { verifyBundle: async (path) => {
      assert.equal(path, bundle);
      return verified;
    } };
    const result = await prepareStandaloneGenesisReviewPacket(directory, dependencies);
    assert.equal(result.status, "untrusted-human-review-required");
    assert.equal(result.releaseQualified, false);
    assert.equal(result.candidateSha256, sha(candidateBytes));
    assert.equal(result.pinSha256, sha(pinBytes));
    assert.equal((await lstat(result.path)).mode & 0o077, 0);
    assert.match(await readFile(result.path, "utf8"), /Signed-source revision/u);
    await assert.rejects(prepareStandaloneGenesisReviewPacket(directory, dependencies), { code: "EEXIST" });
    await unlink(candidatePath);
    await symlink(join(directory, "setup-record.json"), candidatePath);
    await assert.rejects(prepareStandaloneGenesisReviewPacket(directory, dependencies));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
