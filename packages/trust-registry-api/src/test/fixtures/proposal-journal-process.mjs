import process from "node:process";

import {
  FileProposalSubmissionJournal,
  ProposalSubmissionAlreadyPendingError,
  ProposalSubmissionBlockedByReservationError,
  ProposalSubmissionOutcomeUnknownError,
} from "@midnight-ntwrk/trust-registry-api";
import { createPinnedLocalSubmissionProvider } from "@midnight-ntwrk/trust-registry-integration/local-pinned-submission-provider";

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
// Every fork has fresh provider-local guards; only the journal persists across forks.
const provider = createPinnedLocalSubmissionProvider({
  nodeWsUrl: "ws://127.0.0.1:9944",
  indexerHttpUrl: "http://127.0.0.1:8088",
  indexerWsUrl: "ws://127.0.0.1:8089",
  allowedHosts: ["127.0.0.1"],
  contractAddress: contract,
  expectedGenesisHash: genesis,
});
if (typeof provider.midnightProvider.submitTx !== "function") {
  throw new Error("Pinned submission provider was not recreated");
}
process.send("provider-created");

async function submit(role, id, failAfterBroadcast = false) {
  return journal.executeOnce(role, id, evidence, async () => {
    // This callback is the SDK submission seam; no node connection is made in this test.
    process.send("submission-callback");
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
} else if (operation === "reservation-write-failure") {
  await journal.bindDeployment("registry:local", contract, genesis);
  journal.writeAtomically = async () => { throw new Error("injected reservation persistence failure"); };
  try {
    await submit("issuer", "issuer:1");
    throw new Error("Submission proceeded after reservation write failure");
  } catch (error) {
    if (error.message !== "injected reservation persistence failure") throw error;
    process.send("blocked");
  }
} else {
  throw new Error("Unknown child operation");
}

await new Promise((resolveSend, rejectSend) => {
  process.send("complete", (error) => error ? rejectSend(error) : resolveSend());
});
process.disconnect();
