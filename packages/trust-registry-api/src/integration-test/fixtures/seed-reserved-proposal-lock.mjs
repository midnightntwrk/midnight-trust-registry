import { writeFile } from "node:fs/promises";
import process from "node:process";

import { withExclusiveWorkspaceWrite } from "@midnight-ntwrk/trust-registry-cli";

const [journalPath, role, authorizationId, evidenceCommitment] = process.argv.slice(2);
if (journalPath === undefined || role === undefined || authorizationId === undefined
  || evidenceCommitment === undefined || process.send === undefined) {
  throw new Error("Journal path, reservation fields, and IPC channel are required");
}

let release;
const released = new Promise((resolve) => { release = resolve; });
process.on("message", (message) => {
  if (message === "release") release();
});
process.on("disconnect", () => release());

await withExclusiveWorkspaceWrite(journalPath, async () => {
  await writeFile(journalPath, JSON.stringify({
    version: 1,
    attempts: [{ role, authorizationId, evidenceCommitment, state: "reserved", eventHash: null }],
  }), { mode: 0o600 });
  process.send("locked");
  await released;
});
process.disconnect();
