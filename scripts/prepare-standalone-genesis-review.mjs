#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { lstat, link, open, realpath, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { regularBytes } from "./standalone-setup-wizard.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PROJECT = /^tr-standalone-local-[a-z0-9][a-z0-9-]*[a-z0-9]$/u;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const exactFields = (value, fields) => value !== null && typeof value === "object"
  && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");
const validLoopbackRpcUrl = (value) => {
  const match = typeof value === "string"
    ? /^http:\/\/127\.0\.0\.1:([1-9][0-9]*)$/u.exec(value) : null;
  return match !== null && Number(match[1]) >= 1024 && Number(match[1]) <= 65535;
};

export function validateGenesisReviewEvidence(record, candidate, pin, verified) {
  const profile = getLocalNetworkProfile();
  if (!record || !exactFields(record.networkProfile,
    ["id", "networkId", "kind", "genesisPinPolicy"])
    || JSON.stringify(record.networkProfile) !== JSON.stringify(profile)
    || !REVISION.test(record.sourceRevision ?? "")
    || !SHA256.test(record.install?.inventorySha256 ?? "")
    || !PROJECT.test(record.stack?.project ?? "")
    || record.stack?.state !== "observed-ledger-bridge-only"
    || !record.stack.observation
    || verified.sourceRevision !== record.sourceRevision
    || verified.inventorySha256 !== record.install.inventorySha256
    || !Array.isArray(verified.images)) {
    throw new Error("Review packet requires a verified profiled standalone installation");
  }
  const nodeImage = verified.images.find((image) => image.role === "node");
  if (!nodeImage || typeof nodeImage.reference !== "string"
    || !/^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$/u.test(nodeImage.reference)) {
    throw new Error("Review packet requires the pinned node image identity");
  }
  if (!exactFields(candidate, ["format", "sourceRevision", "installInventorySha256",
    "project", "networkId", "nodeReportedGenesisHash", "nodeReportedFinalizedBlockHash",
    "nodeReportedFinalizedHeight", "observerSha256", "observedAt", "status"])
    || candidate.format !== "tr-local-genesis-candidate-v1"
    || candidate.status !== "untrusted-node-observation-independent-review-required"
    || candidate.sourceRevision !== record.sourceRevision
    || candidate.installInventorySha256 !== verified.inventorySha256
    || candidate.project !== record.stack.project
    || candidate.networkId !== profile.networkId
    || !HASH.test(candidate.nodeReportedGenesisHash)
    || /^0x0{64}$/u.test(candidate.nodeReportedGenesisHash)
    || !HASH.test(candidate.nodeReportedFinalizedBlockHash)
    || !Number.isSafeInteger(candidate.nodeReportedFinalizedHeight)
    || candidate.nodeReportedFinalizedHeight < 1
    || !SHA256.test(candidate.observerSha256)
    || typeof candidate.observedAt !== "string"
    || !Number.isFinite(Date.parse(candidate.observedAt))
    || new Date(Date.parse(candidate.observedAt)).toISOString() !== candidate.observedAt) {
    throw new Error("Untrusted genesis candidate differs from the observed installation");
  }
  if (!exactFields(pin, ["format", "networkId", "sourceRevision", "rpcUrl",
    "expectedGenesisHash", "allowedHosts"])
    || pin.format !== "tr-local-ledger-pin-v1"
    || pin.networkId !== profile.networkId
    || pin.sourceRevision !== record.sourceRevision
    || pin.expectedGenesisHash !== candidate.nodeReportedGenesisHash
    || !validLoopbackRpcUrl(pin.rpcUrl)
    || JSON.stringify(pin.allowedHosts) !== '["127.0.0.1"]') {
    throw new Error("Proposed genesis pin differs from the untrusted candidate");
  }
  return { sourceRevision: record.sourceRevision, project: record.stack.project,
    networkId: profile.networkId, inventorySha256: verified.inventorySha256,
    nodeImage: nodeImage.reference, nodeReportedGenesisHash: candidate.nodeReportedGenesisHash,
    observedAt: candidate.observedAt, rpcUrl: pin.rpcUrl };
}

export function renderGenesisReviewPacket(evidence, candidateSha256, pinSha256) {
  if (!SHA256.test(candidateSha256) || !SHA256.test(pinSha256)) {
    throw new Error("Review packet requires exact candidate and pin digests");
  }
  return `# Standalone genesis review packet (UNTRUSTED)

This packet is **not an approval**. All genesis and finality values below came
from the same local node. Matching them to each other does not establish the
genesis of an independently reviewed chain specification. No deployment or
maintenance transition is authorized by this packet.

| Selected input | Value |
| --- | --- |
| Signed-source revision to authenticate | \`${evidence.sourceRevision}\` |
| Install inventory SHA-256 to compare out of band | \`${evidence.inventorySha256}\` |
| Pinned node image | \`${evidence.nodeImage}\` |
| Isolated project / network | \`${evidence.project}\` / \`${evidence.networkId}\` |
| Candidate file SHA-256 | \`${candidateSha256}\` |
| Proposed pin file SHA-256 | \`${pinSha256}\` |
| Node-reported genesis hash (UNTRUSTED) | \`${evidence.nodeReportedGenesisHash}\` |
| Node observation time | \`${evidence.observedAt}\` |
| Proposed installation-only RPC URL | \`${evidence.rpcUrl}\` |

## Human reviewer decisions

1. Obtain the node image provenance and chain specification through a channel
   controlled independently of this running node and this packet. Authenticate
   the source commit signer and independently approved inventory digest.
2. Derive or verify the genesis hash from that independently reviewed
   specification. Compare it with the proposed pin and record the specification
   digest as the stable reviewed reference. A ticket ID is optional; a digest
   of only this candidate or node output is **not** independent evidence.
3. Confirm the exact source, network profile, loopback endpoint, and custody
   boundary. If any value differs, stop and investigate; do not edit this packet
   into an approval or use a \`demo:\` reference.
4. Only after independent review, run the wizard's \`observe\` and
   \`draft-genesis\` steps. Review and sign the exact generated unsigned
   approval bytes with the human reviewer's own GPG key. Never sign this packet
   or use a node-reported hash alone as the approval.

The separate governance-approved maintenance roster, authenticated finalized
deployment/readback, offline actor journeys, restore, and independent security
review remain release gates. This packet does not close any of them.
`;
}

export async function prepareStandaloneGenesisReviewPacket(directory,
  dependencies = {}) {
  const requested = resolve(directory);
  const stat = await lstat(requested);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Review packet requires an owned mode-0700 setup directory");
  }
  const root = await realpath(requested);
  const [recordBytes, candidateBytes, pinBytes] = await Promise.all([
    regularBytes(join(root, "setup-record.json"), { privateFile: true }),
    regularBytes(join(root, "genesis-candidate.untrusted.json"), { privateFile: true }),
    regularBytes(join(root, "genesis-pin.proposed.json"), { privateFile: true }),
  ]);
  const record = JSON.parse(recordBytes.toString("utf8"));
  const candidate = JSON.parse(candidateBytes.toString("utf8"));
  const pin = JSON.parse(pinBytes.toString("utf8"));
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
  const evidence = validateGenesisReviewEvidence(record, candidate, pin, verified);
  const output = join(root, "genesis-review-packet.md");
  const temporary = `${output}.${process.pid}.${randomUUID()}.tmp`;
  const file = await open(temporary, "wx", 0o600);
  try {
    try {
      await file.writeFile(renderGenesisReviewPacket(evidence,
        digest(candidateBytes), digest(pinBytes)));
      await file.sync();
    } finally {
      await file.close();
    }
    await link(temporary, output);
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return { path: output, sourceRevision: evidence.sourceRevision,
    candidateSha256: digest(candidateBytes), pinSha256: digest(pinBytes),
    status: "untrusted-human-review-required", releaseQualified: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/prepare-standalone-genesis-review.mjs <private-setup-dir>");
  }
  console.log(JSON.stringify(await prepareStandaloneGenesisReviewPacket(process.argv[2])));
}
