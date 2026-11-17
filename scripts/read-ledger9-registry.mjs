import { lstat, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { checkLedger9LocalStack, localnetInputFromEnvironment } from "./check-ledger9-local-stack.mjs";

const ADDRESS = /^0x[0-9a-f]{64}$/u;
const hex32 = (value) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error("Finalized epoch contains a non-bytes32 commitment");
  }
  return `0x${Buffer.from(value).toString("hex")}`;
};

export function parseRegistryReadArgs(args, env = process.env) {
  let contractAddress;
  let issuerLabel;
  let verifierLabel;
  let auditorLabel;
  let manifestPath;
  let epochId;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value || !["--address", "--issuer-label", "--verifier-label", "--auditor-label", "--manifest", "--epoch-id"].includes(flag)) {
      throw new Error("Usage: read-ledger9-registry.mjs --address 0x... [--issuer-label label] [--verifier-label label] [--auditor-label label] [--manifest path] [--epoch-id 0x...]");
    }
    if (flag === "--address" && contractAddress === undefined) contractAddress = value;
    else if (flag === "--issuer-label" && issuerLabel === undefined) issuerLabel = value;
    else if (flag === "--verifier-label" && verifierLabel === undefined) verifierLabel = value;
    else if (flag === "--auditor-label" && auditorLabel === undefined) auditorLabel = value;
    else if (flag === "--manifest" && manifestPath === undefined) manifestPath = value;
    else if (flag === "--epoch-id" && epochId === undefined) epochId = value;
    else throw new Error(`Duplicate option: ${flag}`);
  }
  if (!ADDRESS.test(contractAddress ?? "") || /^0x0{64}$/u.test(contractAddress)) {
    throw new Error("A nonzero, lowercase 0x-prefixed contract address is required");
  }
  if (issuerLabel !== undefined && (issuerLabel.length === 0 || issuerLabel.length > 256
    || issuerLabel.trim() !== issuerLabel || issuerLabel.includes("\0"))) {
    throw new Error("Issuer label is invalid");
  }
  if (verifierLabel !== undefined && (verifierLabel.length === 0 || verifierLabel.length > 256
    || verifierLabel.trim() !== verifierLabel || verifierLabel.includes("\0"))) {
    throw new Error("Verifier label is invalid");
  }
  if (auditorLabel !== undefined && (auditorLabel.length === 0 || auditorLabel.length > 256
    || auditorLabel.trim() !== auditorLabel || auditorLabel.includes("\0"))) {
    throw new Error("Auditor label is invalid");
  }
  if (epochId !== undefined && (!ADDRESS.test(epochId) || /^0x0{64}$/u.test(epochId))) {
    throw new Error("Epoch id must be a nonzero lowercase bytes32 commitment");
  }
  if (!ADDRESS.test(env.TR_EXPECTED_GENESIS_HASH ?? "")
    || !ADDRESS.test(env.TR_EXPECTED_CHECKPOINT_HASH ?? "")
    || !Number.isSafeInteger(Number(env.TR_EXPECTED_CHECKPOINT_HEIGHT))
    || Number(env.TR_EXPECTED_CHECKPOINT_HEIGHT) < 1) {
    throw new Error("Pin TR_EXPECTED_GENESIS_HASH and a non-genesis checkpoint height/hash before reading registry state");
  }
  return { contractAddress, issuerLabel, verifierLabel, auditorLabel, manifestPath, epochId };
}

export function assertFinalizedVerifierKeyCatalog(image, manifest, circuitNames) {
  const hashes = manifest?.verifierKeySha256;
  const expected = [...circuitNames].sort();
  if (!["tr-release-candidate-manifest-v2", "tr-release-candidate-manifest-v3"].includes(manifest?.format)
    || !/^[0-9a-f]{40}$/u.test(manifest?.sourceRevision ?? "")
    || hashes === null || typeof hashes !== "object" || Array.isArray(hashes)
    || expected.length === 0 || new Set(expected).size !== expected.length
    || !sameNames(Object.keys(hashes), expected)
    || expected.some((name) => !/^[0-9a-f]{64}$/u.test(hashes[name]))) {
    throw new Error("Release manifest has an invalid or incomplete verifier-key catalog");
  }
  if (!sameNames(Object.keys(image.verifierKeySha256), expected)
    || expected.some((name) => image.verifierKeySha256[name] !== hashes[name])) {
    throw new Error("Finalized verifier keys disagree with the source-matched release manifest");
  }
  return { sourceRevision: manifest.sourceRevision, verifierKeyCatalogMatched: true };
}

function sameNames(left, right) {
  return left.length === right.length && left.sort().every((name, index) => name === right[index]);
}

async function readBoundedManifest(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
    throw new Error("Release manifest must be a bounded regular file");
  }
  return JSON.parse(await readFile(path, "utf8"));
}

function summarizeEpoch(ledger, id) {
  if (!ledger.epochCommitmentIds.member(id)) return null;
  const record = ledger.epochCommitmentRecords.lookup(id);
  if (hex32(record.epochId) !== hex32(id)) {
    throw new Error("Finalized epoch record has a different identifier");
  }
  return {
    idCommitment: hex32(id),
    stateRoot: hex32(record.stateRoot),
    eventRoot: hex32(record.eventRoot),
    policyRoot: hex32(record.policyRoot),
    publicationPolicyCommitment: hex32(record.publicationPolicyCommitment),
    publicationEventHash: hex32(record.publicationEventHash),
    validFromSequence: record.validFromSequence.toString(),
    validUntilSequence: record.validUntilSequence.toString(),
    publishedAtSequence: record.publishedAtSequence.toString(),
  };
}

export function summarizeFinalizedRegistry(image, attached, contractAddress, issuerSelection, epochId,
  verifierSelection, auditorSelection) {
  if (!image || image.networkId !== "undeployed") {
    throw new Error("Finalized Ledger 9 registry image is unavailable for this contract");
  }
  const ledger = image.ledger;
  const issuer = issuerSelection && ledger.issuerAuthorizationRecords.member(issuerSelection.id)
    ? ledger.issuerAuthorizationRecords.lookup(issuerSelection.id) : null;
  const issuerStatus = issuer === null ? null : issuerSelection.statusNames[issuer.status];
  if (issuer !== null && typeof issuerStatus !== "string") {
    throw new Error("Finalized issuer has an unknown authorization status");
  }
  const verifier = verifierSelection && ledger.verifierAuthorizationRecords.member(verifierSelection.id)
    ? ledger.verifierAuthorizationRecords.lookup(verifierSelection.id) : null;
  const verifierStatus = verifier === null ? null : verifierSelection.statusNames[verifier.status];
  if (verifier !== null && typeof verifierStatus !== "string") {
    throw new Error("Finalized verifier has an unknown authorization status");
  }
  const auditor = auditorSelection && ledger.auditorAuthorizationRecords.member(auditorSelection.id)
    ? ledger.auditorAuthorizationRecords.lookup(auditorSelection.id) : null;
  const auditorStatus = auditor === null ? null : auditorSelection.statusNames[auditor.status];
  if (auditor !== null && typeof auditorStatus !== "string") {
    throw new Error("Finalized auditor has an unknown authorization status");
  }
  let currentEpoch = null;
  if (ledger.epochCommitmentCount > 0n) {
    const id = ledger.latestEpochCommitmentId;
    if (!ledger.epochCommitmentIds.member(id)) {
      throw new Error("Finalized latest epoch is absent from the commitment index");
    }
    currentEpoch = summarizeEpoch(ledger, id);
  }
  const selectedEpoch = epochId === undefined ? undefined
    : summarizeEpoch(ledger, Buffer.from(epochId.slice(2), "hex"));
  const issuerLifecycleEventRoot = issuer === null ? null : hex32(issuer.lifecycleEventHash);
  const verifierLifecycleEventRoot = verifier === null ? null : hex32(verifier.lifecycleEventHash);
  const auditorLifecycleEventRoot = auditor === null ? null : hex32(auditor.lifecycleEventHash);
  const decisionEpoch = selectedEpoch === undefined ? currentEpoch : selectedEpoch;
  return {
    network: "undeployed",
    nodeVersion: attached.nodeVersion,
    protocolVersion: attached.protocolVersion,
    genesisHash: attached.genesisHash,
    indexedHeight: attached.indexedHeight,
    contractAddress,
    finalizedBlockHash: image.finalizedBlockHash,
    verifierKeyCount: Object.keys(image.verifierKeySha256).length,
    maintenanceCounter: image.maintenanceAuthority.counter.toString(),
    governanceActionCount: ledger.governanceActionCount.toString(),
    publishedEpochCount: ledger.epochCommitmentCount.toString(),
    currentEpoch,
    ...(epochId === undefined ? {} : { selectedEpoch }),
    activeMaintainers: ledger.activeMaintainerCount.toString(),
    requiredEpochPublishSigners: ledger.maintainerThreshold.toString(),
    evidenceVerifierKeys: ledger.evidenceVerifierKeyCount.toString(),
    activeIssuers: ledger.activeIssuerAuthorizationCount.toString(),
    activeVerifiers: ledger.activeVerifierAuthorizationCount.toString(),
    activeAuditors: ledger.activeAuditorAuthorizationCount.toString(),
    activeRecognitions: ledger.activeRecognitionCount.toString(),
    ...(issuerSelection === undefined ? {} : { issuer: issuer === null
      ? { label: issuerSelection.label, found: false }
      : { label: issuerSelection.label, found: true, status: issuerStatus,
        proposedAtSequence: issuer.proposedAtSequence.toString(),
        authorizedAtSequence: issuer.authorizedAtSequence.toString(),
        activeFromSequence: issuer.activeFromSequence.toString(),
        lifecycleEventRoot: issuerLifecycleEventRoot,
        epochEventRootMatchesLifecycle: decisionEpoch !== null
          && decisionEpoch.eventRoot === issuerLifecycleEventRoot } }),
    ...(verifierSelection === undefined ? {} : { verifier: verifier === null
      ? { label: verifierSelection.label, found: false }
      : { label: verifierSelection.label, found: true, status: verifierStatus,
        proposedAtSequence: verifier.proposedAtSequence.toString(),
        authorizedAtSequence: verifier.authorizedAtSequence.toString(),
        activeFromSequence: verifier.activeFromSequence.toString(),
        lifecycleEventRoot: verifierLifecycleEventRoot,
        epochEventRootMatchesLifecycle: decisionEpoch !== null
          && decisionEpoch.eventRoot === verifierLifecycleEventRoot } }),
    ...(auditorSelection === undefined ? {} : { auditor: auditor === null
      ? { label: auditorSelection.label, found: false }
      : { label: auditorSelection.label, found: true, status: auditorStatus,
        proposedAtSequence: auditor.proposedAtSequence.toString(),
        authorizedAtSequence: auditor.authorizedAtSequence.toString(),
        activeFromSequence: auditor.activeFromSequence.toString(),
        lifecycleEventRoot: auditorLifecycleEventRoot,
        epochEventRootMatchesLifecycle: decisionEpoch !== null
          && decisionEpoch.eventRoot === auditorLifecycleEventRoot } }),
  };
}

export async function readLedger9Registry(args = process.argv.slice(2), env = process.env) {
  const { contractAddress, issuerLabel, verifierLabel, auditorLabel, manifestPath, epochId } = parseRegistryReadArgs(args, env);
  const attached = await checkLedger9LocalStack(localnetInputFromEnvironment(env));
  const [{ bytes32Commitment }, { AuthorizationStatus, TrustRegistryContract, trustRegistryWitnesses },
    { createLocalNetworkDeploymentActionReader }] =
    await Promise.all([
      import("@midnight-ntwrk/trust-registry-client"),
      import("@midnight-ntwrk/trust-registry-contract"),
      import("@midnight-ntwrk/trust-registry-integration"),
    ]);
  const network = {
    networkId: "undeployed",
    expectedGenesisHash: attached.genesisHash,
    rpcUrl: attached.urls.nodeRpcUrl,
    indexerHttpUrl: attached.urls.indexerHttpUrl,
    indexerWsUrl: attached.urls.indexerWsUrl,
    allowedHosts: ["127.0.0.1"],
  };
  const reader = await createLocalNetworkDeploymentActionReader(network);
  const image = await reader.readCurrentFinalizedLedger(contractAddress);
  const issuerSelection = issuerLabel === undefined ? undefined : {
    label: issuerLabel, id: bytes32Commitment(issuerLabel), statusNames: AuthorizationStatus,
  };
  const verifierSelection = verifierLabel === undefined ? undefined : {
    label: verifierLabel, id: bytes32Commitment(verifierLabel), statusNames: AuthorizationStatus,
  };
  const auditorSelection = auditorLabel === undefined ? undefined : {
    label: auditorLabel, id: bytes32Commitment(auditorLabel), statusNames: AuthorizationStatus,
  };
  const catalog = manifestPath === undefined ? {} : assertFinalizedVerifierKeyCatalog(
    image,
    await readBoundedManifest(manifestPath),
    Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits),
  );
  return { ...summarizeFinalizedRegistry(image, attached, contractAddress, issuerSelection, epochId, verifierSelection,
    auditorSelection),
    ...catalog };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    console.log(JSON.stringify(await readLedger9Registry()));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
