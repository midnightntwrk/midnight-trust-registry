import process from "node:process";

import {
  FileProposalSubmissionJournal,
  ProposalSubmissionAlreadyPendingError,
  ProposalSubmissionBlockedByReservationError,
  ProposalSubmissionOutcomeUnknownError,
} from "@midnight-ntwrk/trust-registry-api";

const [path, operation] = process.argv.slice(2);
if (!path || !operation || typeof process.send !== "function") {
  throw new Error("Journal path, operation, and IPC channel are required");
}

const genesis = `0x${"aa".repeat(32)}`;
const contract = `0x${"bb".repeat(32)}`;
const evidence = `0x${"cc".repeat(32)}`;
const event = `0x${"dd".repeat(32)}`;
const context = { actionSequence: "7", actionKind: `0x${"ee".repeat(32)}`,
  actionPayloadHash: `0x${"ff".repeat(32)}` };
const journal = new FileProposalSubmissionJournal(path);

async function submit(role, id, failAfterBroadcast = false) {
  return journal.executeOnce(role, id, evidence, async () => {
    process.send("broadcast");
    if (failAfterBroadcast) throw new Error("provider response lost");
    return { eventHash: event };
  }, context);
}

if (operation === "reserve") {
  await journal.bindDeployment("registry:local", contract, genesis);
  try {
    await submit("issuer", "issuer:1", true);
    throw new Error("Ambiguous provider response was not quarantined");
  } catch (error) {
    if (!(error instanceof ProposalSubmissionOutcomeUnknownError)) throw error;
  }
} else if (operation === "retry" || operation === "other") {
  await journal.assertDeploymentBinding("registry:local", contract, genesis);
  try {
    await submit(operation === "retry" ? "issuer" : "verifier",
      operation === "retry" ? "issuer:1" : "verifier:2");
    if (operation === "retry") throw new Error("A second broadcast was permitted");
  } catch (error) {
    if (operation === "retry" && error instanceof ProposalSubmissionAlreadyPendingError) {
      process.send("blocked");
    } else if (operation === "other" && error instanceof ProposalSubmissionBlockedByReservationError) {
      process.send("blocked");
    } else {
      throw error;
    }
  }
} else if (operation === "lagging" || operation === "observed") {
  await journal.assertDeploymentBinding("registry:local", contract, genesis);
  const result = await journal.reconcile("issuer", "issuer:1", async () => operation === "lagging"
    ? null : { eventHash: event, evidenceCommitment: evidence });
  if (result.state !== (operation === "lagging" ? "reserved" : "observed")) {
    throw new Error("Finalized reconciliation changed the wrong journal state");
  }
} else if (operation === "write-failure") {
  try {
    await submit("issuer", "issuer:1");
    throw new Error("Submission proceeded without a durable journal");
  } catch (error) {
    if (error.message === "Submission proceeded without a durable journal") throw error;
    process.send("blocked");
  }
} else {
  throw new Error("Unknown child operation");
}

await new Promise((resolveSend, rejectSend) => {
  process.send("complete", (error) => error ? rejectSend(error) : resolveSend());
});
process.disconnect();
