import process from "node:process";

const [revision, workflow] = process.argv.slice(2);
const workflows = new Set(["ci.yaml", "quality.yaml", "scan.yaml"]);

try {
  if (!/^[a-f0-9]{40}$/u.test(revision ?? "") || !workflows.has(workflow)) {
    throw new Error("Expected an exact source SHA and release workflow filename");
  }
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  const runs = JSON.parse(input);
  if (!Array.isArray(runs) || !runs.some((run) => run?.event === "push"
    && run.headBranch === "develop" && run.headSha === revision && run.conclusion === "success")) {
    throw new Error(`Successful ${workflow} push run on develop for ${revision} is required`);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : "Release CI verification failed");
  process.exitCode = 1;
}
