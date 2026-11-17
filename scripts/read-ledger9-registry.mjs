import { fileURLToPath } from "node:url";

import { checkLedger9LocalStack, localnetInputFromEnvironment } from "./check-ledger9-local-stack.mjs";

const ADDRESS = /^0x[0-9a-f]{64}$/u;

export function parseRegistryReadArgs(args, env = process.env) {
  let contractAddress;
  let issuerLabel;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value || !["--address", "--issuer-label"].includes(flag)) {
      throw new Error("Usage: read-ledger9-registry.mjs --address 0x... [--issuer-label label]");
    }
    if (flag === "--address" && contractAddress === undefined) contractAddress = value;
    else if (flag === "--issuer-label" && issuerLabel === undefined) issuerLabel = value;
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
  return { contractAddress, issuerLabel };
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
    activeMaintainers: ledger.activeMaintainerCount.toString(),
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
  const { contractAddress, issuerLabel } = parseRegistryReadArgs(args, env);
  const attached = await checkLedger9LocalStack(localnetInputFromEnvironment(env));
  const [{ bytes32Commitment }, { AuthorizationStatus }, { createLocalNetworkDeploymentActionReader }] =
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
  return summarizeFinalizedRegistry(image, attached, contractAddress, issuerSelection);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    console.log(JSON.stringify(await readLedger9Registry()));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
