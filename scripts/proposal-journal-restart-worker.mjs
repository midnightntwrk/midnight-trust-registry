import { appendFile } from "node:fs/promises";

import {
  FileProposalSubmissionJournal,
  ProposalSubmissionAlreadyPendingError,
  ProposalSubmissionOutcomeUnknownError,
} from "../packages/trust-registry-api/dist/proposal-submission-journal.js";

const [phase, journalPath, broadcastPath] = process.argv.slice(2);
const registryId = "registry:restart-proof";
const contractAddress = `0x${"a".repeat(64)}`;
const genesisHash = `0x${"b".repeat(64)}`;
const authorizationId = "issuer:restart-proof";
const evidenceCommitment = `0x${"c".repeat(64)}`;
const eventHash = `0x${"d".repeat(64)}`;
const reservationContext = {
  actionSequence: "3",
  actionKind: `0x${"e".repeat(64)}`,
  actionPayloadHash: `0x${"f".repeat(64)}`,
};

const journal = new FileProposalSubmissionJournal(journalPath);
if (phase === "reserve") {
  await journal.bindDeployment(registryId, contractAddress, genesisHash);
} else {
  await journal.assertDeploymentBinding(registryId, contractAddress, genesisHash);
}

const execute = () => journal.executeOnce("issuer", authorizationId, evidenceCommitment,
  async () => {
    await appendFile(broadcastPath, "broadcast\n");
    throw new Error("SDK response lost after broadcast");
  }, reservationContext);

let state;
if (phase === "reserve") {
  try {
    await execute();
    throw new Error("Ambiguous submission unexpectedly succeeded");
  } catch (error) {
    if (!(error instanceof ProposalSubmissionOutcomeUnknownError)) throw error;
  }
  state = (await journal.read("issuer", authorizationId))?.state;
} else if (phase === "retry" || phase === "replay") {
  try {
    await execute();
    throw new Error("Duplicate submission unexpectedly succeeded");
  } catch (error) {
    if (!(error instanceof ProposalSubmissionAlreadyPendingError)) throw error;
  }
  state = (await journal.read("issuer", authorizationId))?.state;
} else if (phase === "reconcile") {
  const pending = await journal.reconcile("issuer", authorizationId, async () => null);
  if (pending.state !== "reserved") throw new Error("Unobserved reservation was released");
  const observed = await journal.reconcile("issuer", authorizationId,
    async () => ({ eventHash, evidenceCommitment }));
  state = observed.state;
} else {
  throw new Error("Unknown journal restart phase");
}

process.stdout.write(`${JSON.stringify({ phase, state })}\n`);
