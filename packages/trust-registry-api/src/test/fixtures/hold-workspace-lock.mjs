import { withExclusiveWorkspaceWrite } from "@midnight-ntwrk/trust-registry-cli";
import process from "node:process";

const workspacePath = process.argv[2];
if (workspacePath === undefined || process.send === undefined) {
  throw new Error("Workspace path and IPC channel are required");
}

let release;
const released = new Promise((resolve) => { release = resolve; });
process.on("message", (message) => {
  if (message === "release") release();
});
process.on("disconnect", () => release());

await withExclusiveWorkspaceWrite(workspacePath, async () => {
  process.send("locked");
  await released;
});
process.disconnect();
