import { lstat, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { checkLedger9LocalStack, localnetInputFromEnvironment } from "./check-ledger9-local-stack.mjs";

const ADDRESS = /^0x[0-9a-f]{64}$/u;

export function parseRegistryReadArgs(args, env = process.env) {
  let contractAddress;
  let issuerLabel;
  let manifestPath;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value || !["--address", "--issuer-label", "--manifest"].includes(flag)) {
      throw new Error("Usage: read-ledger9-registry.mjs --address 0x... [--issuer-label label] [--manifest path]");
    }
    if (flag === "--address" && contractAddress === undefined) contractAddress = value;
    else if (flag === "--issuer-label" && issuerLabel === undefined) issuerLabel = value;
    else if (flag === "--manifest" && manifestPath === undefined) manifestPath = value;
    else throw new Error(`Duplicate option: ${flag}`);
  }
  if (!ADDRESS.test(contractAddress ?? "") || /^0x0{64}$/u.test(contractAddress)) {
    throw new Error("A nonzero, lowercase 0x-prefixed contract address is required");
  }
  if (issuerLabel !== undefined && (issuerLabel.length === 0 || issuerLabel.length > 256
    || issuerLabel.trim() !== issuerLabel || issuerLabel.includes("\0"))) {
    throw new Error("Issuer label is invalid");
  }
  if (!ADDRESS.test(env.TR_EXPECTED_GENESIS_HASH ?? "")
    || !ADDRESS.test(env.TR_EXPECTED_CHECKPOINT_HASH ?? "")
    || !Number.isSafeInteger(Number(env.TR_EXPECTED_CHECKPOINT_HEIGHT))
    || Number(env.TR_EXPECTED_CHECKPOINT_HEIGHT) < 1) {
    throw new Error("Pin TR_EXPECTED_GENESIS_HASH and a non-genesis checkpoint height/hash before reading registry state");
  }
  return { contractAddress, issuerLabel, manifestPath };
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

export function summarizeFinalizedRegistry(image, attached, contractAddress, issuerSelection) {
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
        activeFromSequence: issuer.activeFromSequence.toString() } }),
  };
}

export async function readLedger9Registry(args = process.argv.slice(2), env = process.env) {
  const { contractAddress, issuerLabel, manifestPath } = parseRegistryReadArgs(args, env);
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
  const catalog = manifestPath === undefined ? {} : assertFinalizedVerifierKeyCatalog(
    image,
    await readBoundedManifest(manifestPath),
    Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits),
  );
  return { ...summarizeFinalizedRegistry(image, attached, contractAddress, issuerSelection), ...catalog };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    console.log(JSON.stringify(await readLedger9Registry()));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
