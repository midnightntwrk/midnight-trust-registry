import assert from "node:assert/strict";
import { test } from "node:test";

import { assertFinalizedKeylessVerifierKeyCatalog, assertFinalizedVerifierKeyCatalog,
  parseRegistryReadArgs, summarizeFinalizedRegistry } from "./read-ledger9-registry.mjs";

const address = `0x${"a".repeat(64)}`;
const env = {
  TR_EXPECTED_GENESIS_HASH: `0x${"b".repeat(64)}`,
  TR_EXPECTED_CHECKPOINT_HEIGHT: "10",
  TR_EXPECTED_CHECKPOINT_HASH: `0x${"c".repeat(64)}`,
};

test("registry read requires an exact address and non-genesis chain pin", () => {
  assert.deepEqual(parseRegistryReadArgs(["--address", address, "--issuer-label", "issuer:example"], env), {
    contractAddress: address, issuerLabel: "issuer:example", issuerResourceId: undefined,
    verifierLabel: undefined, auditorLabel: undefined,
    recognitionLabel: undefined,
    manifestPath: undefined, keylessDir: undefined, keylessManifestSha256: undefined,
    expectedSourceRevision: undefined, epochId: undefined,
  });
  assert.equal(parseRegistryReadArgs(["--address", address, "--verifier-label", "verifier:example"], env)
    .verifierLabel, "verifier:example");
  assert.equal(parseRegistryReadArgs(["--address", address, "--auditor-label", "auditor:example"], env)
    .auditorLabel, "auditor:example");
  assert.equal(parseRegistryReadArgs(["--address", address, "--recognition-label", "recognition:example"], env)
    .recognitionLabel, "recognition:example");
  const canonicalResourceId = `tr:issuer-resource:v1:${"d".repeat(64)}`;
  assert.equal(parseRegistryReadArgs(["--address", address, "--issuer-label", "issuer:example",
    "--issuer-resource-id", canonicalResourceId], env).issuerResourceId, canonicalResourceId);
  assert.equal(parseRegistryReadArgs(["--address", address, "--manifest", "release.json"], env).manifestPath,
    "release.json");
  assert.equal(parseRegistryReadArgs(["--address", address, "--manifest", "release.json",
    "--expect-source-revision", "a".repeat(40)], env).expectedSourceRevision, "a".repeat(40));
  assert.equal(parseRegistryReadArgs(["--address", address, "--keyless-dir", "local-candidate",
    "--keyless-manifest-sha256", "b".repeat(64), "--expect-source-revision", "a".repeat(40)], env)
    .keylessDir, "local-candidate");
  assert.equal(parseRegistryReadArgs(["--address", address, "--epoch-id", address], env).epochId, address);
  assert.throws(() => parseRegistryReadArgs(["--address", address], {}), /Pin TR_EXPECTED/u);
  assert.throws(() => parseRegistryReadArgs(["--address", `0x${"0".repeat(64)}`], env), /nonzero/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--address", address], env), /Duplicate/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--manifest", "a", "--manifest", "b"], env), /Duplicate/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address,
    "--expect-source-revision", "a".repeat(40)], env), /requires a manifest/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--manifest", "release.json",
    "--expect-source-revision", "A".repeat(40)], env), /exact lowercase/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--manifest", "release.json",
    "--expect-source-revision", "a".repeat(40), "--expect-source-revision", "a".repeat(40)], env), /Duplicate/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--keyless-dir", "local-candidate"], env),
    /keyless readback requires/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--keyless-manifest-sha256", "b".repeat(64)], env),
    /keyless readback requires/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--manifest", "release.json",
    "--keyless-dir", "local-candidate", "--keyless-manifest-sha256", "b".repeat(64),
    "--expect-source-revision", "a".repeat(40)], env), /mutually exclusive/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--issuer-label", "x\0y"], env), /invalid/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--verifier-label", "x\0y"], env), /invalid/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--auditor-label", "x\0y"], env), /invalid/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--recognition-label", "x\0y"], env), /invalid/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--issuer-resource-id", canonicalResourceId], env),
    /canonical composite/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--issuer-label", "issuer:example",
    "--issuer-resource-id", "schema:local-development-fixture:v1"], env), /canonical composite/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--epoch-id", "0xA"], env), /Epoch id/u);
  assert.throws(() => parseRegistryReadArgs(["--address", address, "--epoch-id", address,
    "--epoch-id", address], env), /Duplicate/u);
});

test("local keyless readback matches every deployed verifier without becoming release evidence", () => {
  const manifest = { format: "tr-keyless-zkir-v1", sourceRevision: "a".repeat(40), keys: {
    "first.prover": "c".repeat(64), "first.verifier": "d".repeat(64),
    "second.prover": "e".repeat(64), "second.verifier": "f".repeat(64),
  } };
  const image = { verifierKeySha256: { first: "d".repeat(64), second: "f".repeat(64) } };
  assert.deepEqual(assertFinalizedKeylessVerifierKeyCatalog(image, manifest, ["first", "second"], "a".repeat(40)), {
    sourceRevision: "a".repeat(40), verifierKeyCatalogMatched: true,
    evidenceKind: "local-keyless-candidate", releaseQualified: false,
  });
  assert.throws(() => assertFinalizedKeylessVerifierKeyCatalog(image, manifest, ["first", "second"], "b".repeat(40)),
    /invalid source/u);
  assert.throws(() => assertFinalizedKeylessVerifierKeyCatalog(image, { ...manifest, keys: {
    "first.prover": "c".repeat(64), "first.verifier": "d".repeat(64),
  } }, ["first", "second"], "a".repeat(40)), /incomplete/u);
  assert.throws(() => assertFinalizedKeylessVerifierKeyCatalog(image, { ...manifest, keys: {
    ...manifest.keys, "second.prover": "not-a-hash",
  } }, ["first", "second"], "a".repeat(40)), /invalid source/u);
  assert.throws(() => assertFinalizedKeylessVerifierKeyCatalog({ verifierKeySha256: {
    first: "d".repeat(64), second: "0".repeat(64),
  } }, manifest, ["first", "second"], "a".repeat(40)), /disagree/u);
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
  assert.deepEqual(assertFinalizedVerifierKeyCatalog(image, manifest, ["first", "second"], "a".repeat(40)), {
    sourceRevision: manifest.sourceRevision, verifierKeyCatalogMatched: true,
  });
  assert.throws(() => assertFinalizedVerifierKeyCatalog(image, manifest, ["first", "second"], "d".repeat(40)),
    /source revision disagrees/u);
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

test("registry read summarizes finalized state and selected actors without leaking a key", () => {
  const issuerLabel = "issuer:example";
  const issuerId = new Uint8Array(32).fill(1);
  const verifierId = new Uint8Array(32).fill(6);
  const auditorId = new Uint8Array(32).fill(8);
  const recognitionId = new Uint8Array(32).fill(10);
  const statusNames = { 2: "active" };
  const record = {
    status: 2,
    proposedAtSequence: 3n,
    authorizedAtSequence: 4n,
    activeFromSequence: 5n,
    resourceId: new Uint8Array(32).fill(3),
    statusPolicyBindingCommitment: new Uint8Array(32).fill(4),
    lifecycleEventHash: new Uint8Array(32).fill(2),
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
      verifierAuthorizationRecords: {
        member: (id) => Buffer.from(id).equals(Buffer.from(verifierId)),
        lookup: () => record,
      },
      auditorAuthorizationRecords: {
        member: (id) => Buffer.from(id).equals(Buffer.from(auditorId)),
        lookup: () => record,
      },
      recognitionRecords: {
        member: (id) => Buffer.from(id).equals(Buffer.from(recognitionId)),
        lookup: () => ({ ...record, effectiveFromSequence: 5n }),
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
  assert.equal(summary.currentEpoch, null);
  assert.equal(summary.requiredEpochPublishSigners, "2");
  assert.deepEqual(summary.issuer, { label: issuerLabel, found: true, status: "active",
    proposedAtSequence: "3", authorizedAtSequence: "4", activeFromSequence: "5",
    statusPolicyBindingCommitment: `0x${"04".repeat(32)}`,
    lifecycleEventRoot: `0x${"02".repeat(32)}`, epochEventRootMatchesLifecycle: false });
  assert.equal(summarizeFinalizedRegistry(image, attached, address,
    { label: issuerLabel, id: issuerId, statusNames,
      resourceIdCommitment: new Uint8Array(32).fill(3) }).issuer.canonicalResourceIdCommitmentMatches, true);
  assert.equal(summarizeFinalizedRegistry(image, attached, address,
    { label: issuerLabel, id: issuerId, statusNames,
      resourceIdCommitment: new Uint8Array(32).fill(9) }).issuer.canonicalResourceIdCommitmentMatches, false);
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address,
    { label: "issuer:unknown", id: new Uint8Array(32).fill(2), statusNames }).issuer,
    { label: "issuer:unknown", found: false });
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address, undefined, undefined,
    { label: "verifier:example", id: verifierId, statusNames }).verifier,
  { label: "verifier:example", found: true, status: "active",
    proposedAtSequence: "3", authorizedAtSequence: "4", activeFromSequence: "5",
    lifecycleEventRoot: `0x${"02".repeat(32)}`, epochEventRootMatchesLifecycle: false });
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address, undefined, undefined,
    { label: "verifier:unknown", id: new Uint8Array(32).fill(7), statusNames }).verifier,
  { label: "verifier:unknown", found: false });
  assert.throws(() => summarizeFinalizedRegistry(image, attached, address, undefined, undefined,
    { label: "verifier:example", id: verifierId, statusNames: {} }), /unknown authorization status/u);
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address, undefined, undefined, undefined,
    { label: "auditor:example", id: auditorId, statusNames }).auditor,
  { label: "auditor:example", found: true, status: "active",
    proposedAtSequence: "3", authorizedAtSequence: "4", activeFromSequence: "5",
    lifecycleEventRoot: `0x${"02".repeat(32)}`, epochEventRootMatchesLifecycle: false });
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address, undefined, undefined, undefined,
    { label: "auditor:unknown", id: new Uint8Array(32).fill(7), statusNames }).auditor,
  { label: "auditor:unknown", found: false });
  assert.throws(() => summarizeFinalizedRegistry(image, attached, address, undefined, undefined, undefined,
    { label: "auditor:example", id: auditorId, statusNames: {} }), /unknown authorization status/u);
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address, undefined, undefined, undefined,
    undefined, { label: "recognition:example", id: recognitionId, statusNames }).recognition,
  { label: "recognition:example", found: true, status: "active",
    proposedAtSequence: "3", authorizedAtSequence: "4", effectiveFromSequence: "5",
    lifecycleEventRoot: `0x${"02".repeat(32)}`, epochEventRootMatchesLifecycle: false });
  assert.deepEqual(summarizeFinalizedRegistry(image, attached, address, undefined, undefined, undefined,
    undefined, { label: "recognition:unknown", id: new Uint8Array(32).fill(7), statusNames }).recognition,
  { label: "recognition:unknown", found: false });
  assert.throws(() => summarizeFinalizedRegistry(image, attached, address, undefined, undefined, undefined,
    undefined, { label: "recognition:example", id: recognitionId, statusNames: {} }), /unknown authorization status/u);
  assert.throws(() => summarizeFinalizedRegistry(image, attached, address,
    { label: issuerLabel, id: issuerId, statusNames: {} }), /unknown authorization status/u);
  assert.throws(() => summarizeFinalizedRegistry(null, attached, address), /unavailable/u);
  const epochId = new Uint8Array(32).fill(9);
  const epoch = {
    epochId, stateRoot: new Uint8Array(32).fill(1), eventRoot: new Uint8Array(32).fill(2),
    policyRoot: new Uint8Array(32).fill(3), publicationPolicyCommitment: new Uint8Array(32).fill(4),
    publicationEventHash: new Uint8Array(32).fill(5),
    validFromSequence: 5n, validUntilSequence: 65n, publishedAtSequence: 5n,
  };
  const withEpoch = { ...image, ledger: { ...image.ledger,
    epochCommitmentCount: 1n, latestEpochCommitmentId: epochId,
    epochCommitmentIds: { member: (id) => Buffer.from(id).equals(Buffer.from(epochId)) },
    epochCommitmentRecords: { lookup: () => epoch },
  } };
  assert.deepEqual(summarizeFinalizedRegistry(withEpoch, attached, address).currentEpoch, {
    idCommitment: `0x${"09".repeat(32)}`,
    stateRoot: `0x${"01".repeat(32)}`,
    eventRoot: `0x${"02".repeat(32)}`,
    policyRoot: `0x${"03".repeat(32)}`,
    publicationPolicyCommitment: `0x${"04".repeat(32)}`,
    publicationEventHash: `0x${"05".repeat(32)}`,
    validFromSequence: "5", validUntilSequence: "65", publishedAtSequence: "5",
  });
  assert.deepEqual(summarizeFinalizedRegistry(withEpoch, attached, address, undefined,
    `0x${"09".repeat(32)}`).selectedEpoch,
  summarizeFinalizedRegistry(withEpoch, attached, address).currentEpoch);
  assert.equal(summarizeFinalizedRegistry(withEpoch, attached, address,
    { label: issuerLabel, id: issuerId, statusNames }).issuer.epochEventRootMatchesLifecycle, true);
  assert.equal(summarizeFinalizedRegistry({ ...withEpoch, ledger: { ...withEpoch.ledger,
    issuerAuthorizationRecords: { ...withEpoch.ledger.issuerAuthorizationRecords,
      lookup: () => ({ ...record, lifecycleEventHash: new Uint8Array(32).fill(7) }) },
  } }, attached, address, { label: issuerLabel, id: issuerId, statusNames }).issuer
    .epochEventRootMatchesLifecycle, false);
  assert.equal(summarizeFinalizedRegistry(withEpoch, attached, address,
    { label: issuerLabel, id: issuerId, statusNames }, `0x${"08".repeat(32)}`).issuer
    .epochEventRootMatchesLifecycle, false);
  assert.equal(summarizeFinalizedRegistry(withEpoch, attached, address, undefined, undefined,
    { label: "verifier:example", id: verifierId, statusNames }).verifier.epochEventRootMatchesLifecycle, true);
  assert.equal(summarizeFinalizedRegistry(withEpoch, attached, address, undefined, undefined, undefined,
    { label: "auditor:example", id: auditorId, statusNames }).auditor.epochEventRootMatchesLifecycle, true);
  assert.equal(summarizeFinalizedRegistry(withEpoch, attached, address, undefined, undefined, undefined,
    undefined, { label: "recognition:example", id: recognitionId, statusNames })
    .recognition.epochEventRootMatchesLifecycle, true);
  assert.equal(summarizeFinalizedRegistry(withEpoch, attached, address, undefined,
    `0x${"08".repeat(32)}`).selectedEpoch, null);
  assert.throws(() => summarizeFinalizedRegistry({ ...withEpoch, ledger: {
    ...withEpoch.ledger, epochCommitmentIds: { member: () => false },
  } }, attached, address), /absent from the commitment index/u);
  assert.throws(() => summarizeFinalizedRegistry({ ...withEpoch, ledger: {
    ...withEpoch.ledger, epochCommitmentRecords: { lookup: () => ({ ...epoch, epochId: new Uint8Array(32) }) },
  } }, attached, address), /different identifier/u);
});
