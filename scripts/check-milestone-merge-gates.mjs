#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY = "midnightntwrk/midnight-trust-registry";
const REQUIRED_CHECKS = ["Milestone Light", "scan", "Typecheck, Audit, and Packaging Baseline"];
const SHA = /^[0-9a-f]{40}$/u;

function fail(message) {
  throw new Error(`Milestone merge gate: ${message}`);
}

export function evaluateMilestoneMergeGate({ pull, commits, checks, statuses, review, finalPull }) {
  const head = pull?.head?.sha;
  if (pull?.state !== "open" || pull?.draft !== false
    || pull?.base?.ref !== "milestone-0.1.0" || !SHA.test(head ?? "")
    || !SHA.test(pull?.base?.sha ?? "") || pull?.mergeable !== true
    || finalPull?.number !== pull.number || finalPull?.state !== "open"
    || finalPull?.draft !== false || finalPull?.base?.ref !== pull.base.ref
    || finalPull?.head?.sha !== head || finalPull?.base?.sha !== pull.base.sha
    || finalPull?.mergeable !== true) {
    fail("PR is draft, closed, conflicting, off-train, or changed during inspection");
  }
  if (!Array.isArray(commits) || commits.length === 0
    || commits.at(-1)?.sha !== head || commits.some((entry) => {
      const verification = entry?.commit?.verification;
      const author = entry?.commit?.author;
      const signoff = entry?.commit?.message?.match(/^Signed-off-by: (.+) <([^<>]+)>$/gmu) ?? [];
      return !SHA.test(entry?.sha ?? "") || verification?.verified !== true
        || verification?.reason !== "valid"
        || !verification?.signature?.startsWith("-----BEGIN PGP SIGNATURE-----")
        || !signoff.some((line) => line === `Signed-off-by: ${author?.name} <${author?.email}>`);
    })) fail("a PR commit lacks verified OpenPGP signing or matching DCO sign-off");

  if (!Array.isArray(checks) || checks.length === 0
    || checks.some((check) => check?.head_sha !== head || typeof check.name !== "string"
      || check.name.length === 0 || !Number.isSafeInteger(check.id))) {
    fail("exact-head check runs are unavailable or malformed");
  }
  const latestChecks = new Map();
  for (const check of checks) {
    const prior = latestChecks.get(check.name);
    if (prior === undefined || check.id > prior.id) latestChecks.set(check.name, check);
  }
  for (const name of REQUIRED_CHECKS) {
    const check = latestChecks.get(name);
    if (check?.status !== "completed" || check.conclusion !== "success") {
      fail(`required exact-head check is not green: ${name}`);
    }
  }
  for (const check of latestChecks.values()) {
    if (check.status !== "completed" || !["success", "skipped"].includes(check.conclusion)) {
      fail(`applicable exact-head check is not green: ${check.name}`);
    }
  }
  if (!Array.isArray(statuses) || statuses.some((status) => (status?.sha != null && status.sha !== head)
    || typeof status.context !== "string" || status.context.length === 0
    || !Number.isFinite(Date.parse(status.created_at)))) {
    fail("exact-head commit statuses are unavailable or malformed");
  }
  const latestStatuses = new Map();
  for (const status of statuses) {
    const prior = latestStatuses.get(status.context);
    if (prior === undefined || Date.parse(status.created_at) > Date.parse(prior.created_at)) {
      latestStatuses.set(status.context, status);
    }
  }
  for (const status of latestStatuses.values()) {
    if (status.state !== "success") fail(`exact-head commit status is not green: ${status.context}`);
  }
  if (review?.format !== "tr-milestone-current-head-review-v1"
    || review.repository !== REPOSITORY || review.pullRequest !== pull.number
    || review.headSha !== head || review.verdict !== "no-blockers"
    || typeof review.reviewer !== "string" || review.reviewer.trim().length === 0
    || typeof review.evidenceReference !== "string" || review.evidenceReference.trim().length === 0
    || typeof review.reviewedAt !== "string"
    || !Number.isFinite(Date.parse(review.reviewedAt))
    || new Date(review.reviewedAt).toISOString() !== review.reviewedAt
    || Date.parse(review.reviewedAt) > Date.now() + 300_000) {
    fail("documented LLM review does not identify this exact head without blockers");
  }
  return { repository: REPOSITORY, pullRequest: pull.number, headSha: head,
    checkedCommits: commits.length, checkedRuns: latestChecks.size,
    checkedStatuses: latestStatuses.size, reviewReference: review.evidenceReference,
    result: "preflight-passed-operator-must-confirm-review-and-merge" };
}

function gh(path) {
  return JSON.parse(execFileSync("gh", ["api", path], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 16 * 1024 * 1024,
  }));
}

function pages(path, select) {
  const entries = [];
  for (let page = 1; page <= 10; page += 1) {
    const result = gh(`${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    const batch = select(result);
    if (!Array.isArray(batch)) fail("GitHub returned a malformed paginated response");
    entries.push(...batch);
    if (batch.length < 100) return entries;
  }
  fail("GitHub result exceeds the bounded pagination limit");
}

export function runMilestoneMergePreflight(number, reviewPath) {
  if (!Number.isSafeInteger(number) || number < 1 || !reviewPath?.startsWith("/")) {
    fail("usage: check-milestone-merge-gates.mjs PR_NUMBER ABSOLUTE_REVIEW_RECORD_JSON");
  }
  const review = JSON.parse(readFileSync(reviewPath, "utf8"));
  const base = `repos/${REPOSITORY}`;
  const pull = gh(`${base}/pulls/${number}`);
  const head = pull?.head?.sha;
  if (!SHA.test(head ?? "")) fail("PR head is unavailable");
  const commits = pages(`${base}/pulls/${number}/commits`, (result) => result);
  const checks = pages(`${base}/commits/${head}/check-runs`, (result) => result?.check_runs);
  const statuses = pages(`${base}/commits/${head}/statuses`, (result) => result);
  const finalPull = gh(`${base}/pulls/${number}`);
  return evaluateMilestoneMergeGate({ pull, commits, checks, statuses, review, finalPull });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4 || !/^[1-9][0-9]*$/u.test(process.argv[2])) {
      fail("usage: check-milestone-merge-gates.mjs PR_NUMBER ABSOLUTE_REVIEW_RECORD_JSON");
    }
    console.log(JSON.stringify(runMilestoneMergePreflight(Number(process.argv[2]), process.argv[3]), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
