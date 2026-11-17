import assert from "node:assert/strict";
import { test } from "node:test";

import { assertFinalizedVerifierKeyCatalog, parseRegistryReadArgs, summarizeFinalizedRegistry } from "./read-ledger9-registry.mjs";

const address = `0x${"a".repeat(64)}`;
const env = {
  TR_EXPECTED_GENESIS_HASH: `0x${"b".repeat(64)}`,
  TR_EXPECTED_CHECKPOINT_HEIGHT: "10",
  TR_EXPECTED_CHECKPOINT_HASH: `0x${"c".repeat(64)}`,
};

test("registry read requires an exact address and non-genesis chain pin", () => {
  assert.deepEqual(parseRegistryReadArgs(["--address", address, "--issuer-label", "issuer:example"], env), {
    contractAddress: address, issuerLabel: "issuer:example", manifestPath: undefined,
  });
  assert.equal(parseRegistryReadArgs(["--address", address, "--manifest", "release.json"], env).manifestPath,
    "release.json");
  assert.throws(() => parseRegistryReadArgs(["--address", address], {}), /Pin TR_EXPECTED/u);
  assert.throws(() => parseRegistryReadArgs(["--address", `0x${"0".repeat(64)}`], env), /nonzero/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--address", address], env), /Duplicate/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--manifest", "a", "--manifest", "b"], env), /Duplicate/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--issuer-label", "x\0y"], env), /invalid/u);
});

test("registry read requires every finalized verifier key to match the source manifest", () => {
  const manifest = {
    format: "tr-release-candidate-manifest-v2",
    sourceRevision: "a".repeat(40),
    verifierKeySha256: { first: "b".repeat(64), second: "c".repeat(64) },
  };
  const image = { verifierKeySha256: { second: "c".repeat(64), first: "b".repeat(64) } };
  assert.deepEqual(assertFinalizedVerifierKeyCatalog(image, manifest, ["first", "second"]), {
    sourceRevision: manifest.sourceRevision, verifierKeyCatalogMatched: true,
  });
  assert.throws(() => assertFinalizedVerifierKeyCatalog(image,
    { ...manifest, verifierKeySha256: { first: "b".repeat(64) } }, ["first", "second"]), /incomplete/u);
  assert.throws(() => assertFinalizedVerifierKeyCatalog(image,
    { ...manifest, verifierKeySha256: { ...manifest.verifierKeySha256, extra: "d".repeat(64) } },
    ["first", "second"]), /incomplete/u);
  assert.throws(() => assertFinalizedVerifierKeyCatalog(
    { verifierKeySha256: { ...image.verifierKeySha256, first: "d".repeat(64) } },
    manifest, ["first", "second"]), /disagree/u);
  assert.throws(() => assertFinalizedVerifierKeyCatalog(
    { verifierKeySha256: { first: "b".repeat(64) } }, manifest, ["first", "second"]), /disagree/u);
});

test("registry read summarizes finalized state and a selected issuer without leaking a key", () => {
  const issuerLabel = "issuer:example";
  const issuerId = new Uint8Array(32).fill(1);
  const statusNames = { 2: "active" };
  const record = {
    status: 2,
    proposedAtSequence: 3n,
    authorizedAtSequence: 4n,
    activeFromSequence: 5n,
  };
  const image = {
    networkId: "undeployed", finalizedBlockHash: `0x${"d".repeat(64)}`,
    verifierKeySha256: { one: "a", two: "b" }, maintenanceAuthority: { counter: 1n },
    ledger: {
      governanceActionCount: 5n, epochCommitmentCount: 0n,
      activeMaintainerCount: 1n, maintainerThreshold: 2n, evidenceVerifierKeyCount: 1n,
      activeIssuerAuthorizationCount: 1n, activeVerifierAuthorizationCount: 0n,
      activeAuditorAuthorizationCount: 0n, activeRecognitionCount: 0n,
      issuerAuthorizationRecords: {
        member: (id) => Buffer.from(id).equals(Buffer.from(issuerId)),
        lookup: () => record,
      },
    },
  };
  const attached = { nodeVersion: "2.1.101", protocolVersion: 2001100,
    genesisHash: env.TR_EXPECTED_GENESIS_HASH, indexedHeight: 12 };
  const summary = summarizeFinalizedRegistry(image, attached, address,
    { label: issuerLabel, id: issuerId, statusNames });
  assert.equal(summary.verifierKeyCount, 2);
  assert.equal(summary.governanceActionCount, "5");
  assert.equal(summary.publishedEpochCount, "0");
  assert.equal(summary.requiredEpochPublishSigners, "2");
  assert.deepEqual(summary.issuer, { label: issuerLabel, found: true, status: "active",
    proposedAtSequence: "3", authorizedAtSequence: "4", activeFromSequence: "5" });
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address,
    { label: "issuer:unknown", id: new Uint8Array(32).fill(2), statusNames }).issuer,
    { label: "issuer:unknown", found: false });
  assert.throws(() => summarizeFinalizedRegistry(image, attached, address,
    { label: issuerLabel, id: issuerId, statusNames: {} }), /unknown authorization status/u);
  assert.throws(() => summarizeFinalizedRegistry(null, attached, address), /unavailable/u);
});
