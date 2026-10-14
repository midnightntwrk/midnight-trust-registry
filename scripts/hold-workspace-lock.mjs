import { withExclusiveWorkspaceWrite } from "../packages/trust-registry-cli/dist/index.js";

const workspacePath = process.argv[2];
if (workspacePath === undefined) throw new Error("workspace path is required");

await withExclusiveWorkspaceWrite(workspacePath, async () => {
  process.stdout.write("locked\n");
  await new Promise((resolve, reject) => {
    process.stdin.once("end", resolve);
    process.stdin.once("error", reject);
    process.stdin.resume();
  });
});
