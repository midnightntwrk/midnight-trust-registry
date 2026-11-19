import { execFileSync } from "node:child_process";
import process from "node:process";

const artifactName = "trust-registry-keyless-prepare-only";

export function validatePrepareRun(run, artifacts, repository, runId, revision) {
  if (!/^[0-9]+$/u.test(runId) || !/^[a-f0-9]{40}$/u.test(revision)
    || String(run?.id) !== runId || run.path !== ".github/workflows/prepare-keyless-release.yaml"
    || run.event !== "workflow_dispatch" || run.head_branch !== "develop" || run.head_sha !== revision
    || run.head_repository?.full_name !== repository || run.repository?.full_name !== repository
    || run.status !== "completed" || run.conclusion !== "success") {
    throw new Error("Require a successful manual Prepare Keyless Release run on the exact develop source");
  }
  const matching = artifacts?.artifacts?.filter((artifact) => artifact?.name === artifactName) ?? [];
  const [artifact] = matching;
  if (matching.length !== 1 || artifact.expired !== false || !Number.isSafeInteger(artifact.id)
    || !/^sha256:[0-9a-f]{64}$/u.test(artifact.digest)) {
    throw new Error("Expected one unexpired, digest-pinned keyless release artifact");
  }
  return { id: artifact.id, sha256: artifact.digest.slice(7) };
}

if (process.argv[1]?.endsWith("/resolve-keyless-prepare-run.mjs")) {
  try {
    const [repository, runId, revision] = process.argv.slice(2);
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository ?? "")
      || !/^[0-9]+$/u.test(runId ?? "") || !/^[a-f0-9]{40}$/u.test(revision ?? "")) {
      throw new Error("Expected repository, prepare run ID, and exact source SHA");
    }
    const api = (path) => JSON.parse(execFileSync("gh", ["api", path], { encoding: "utf8" }));
    const runPath = `repos/${repository}/actions/runs/${runId}`;
    if (api(`repos/${repository}/git/ref/heads/develop`).object.sha !== revision) {
      throw new Error("Develop moved; prepare and review the new exact source");
    }
    console.log(JSON.stringify(validatePrepareRun(api(runPath),
      api(`${runPath}/artifacts?per_page=100`), repository, runId, revision)));
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Prepare run validation failed");
    process.exitCode = 1;
  }
}
