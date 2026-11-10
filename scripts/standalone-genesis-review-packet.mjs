/** @typedef {ReturnType<typeof import("./standalone-genesis-review-policy.mjs").validateGenesisReviewEvidence>} GenesisReviewEvidence */

const SHA256 = /^[0-9a-f]{64}$/u;

/**
 * Render a node-derived proposal for independent review, never an approval.
 * @param {GenesisReviewEvidence} evidence
 * @param {string} candidateSha256
 * @param {string} pinSha256
 */
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
| Isolated Docker project | \`${evidence.project}\` |
| Trust Registry environment profile | \`${evidence.profileId}\` |
| Midnight ledger network ID | \`${evidence.networkId}\` |
| Candidate file SHA-256 | \`${candidateSha256}\` |
| Proposed pin file SHA-256 | \`${pinSha256}\` |
| Node-reported genesis hash (UNTRUSTED) | \`${evidence.nodeReportedGenesisHash}\` |
| Node observation time | \`${evidence.observedAt}\` |
| Proposed installation-only RPC URL | \`${evidence.rpcUrl}\` |

The environment profile selects the per-installation genesis-pin policy.
\`undeployed\` is Midnight's local ledger network identifier, not a statement
that this Trust Registry contract has or has not been deployed. The deployment
receipt and finalized contract readback are separate evidence.

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
