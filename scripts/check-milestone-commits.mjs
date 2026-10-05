import { readFileSync } from 'node:fs';

export function checkCommitSignoffs(commits, trustedShas = new Set()) {
  const errors = [];
  if (commits.length === 0) errors.push('PR contains no authored commits');
  for (const { sha, authorName, authorEmail, committerName, committerEmail, message, verified } of commits) {
    if (verified === false) errors.push(`${sha}: commit signature is not verified`);
    if (trustedShas.has(sha)) continue;
    if (!authorName || !authorEmail || typeof message !== 'string') {
      errors.push(`${sha}: commit author identity or message is missing`);
      continue;
    }
    const allowed = [
      `Signed-off-by: ${authorName} <${authorEmail}>`,
      ...(committerName && committerEmail
        ? [`Signed-off-by: ${committerName} <${committerEmail}>`]
        : []),
    ];
    if (!message.split('\n').some((line) => allowed.includes(line.trim()))) {
      errors.push(`${sha}: missing author- or committer-matching DCO signoff`);
    }
  }
  return errors;
}

async function githubJson(path, token) {
  const response = await fetch(`https://api.github.com/${path}`, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'x-github-api-version': '2022-11-28',
    },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`GitHub API ${path} returned ${response.status}`);
  return response.json();
}

async function pullCommits(repo, number, token) {
  const commits = [];
  for (let page = 1; page <= 3; page += 1) {
    const batch = await githubJson(`repos/${repo}/pulls/${number}/commits?per_page=100&page=${page}`, token);
    commits.push(...batch);
    if (batch.length < 100) return commits;
  }
  return commits;
}

export function assertCompleteCommitList(expectedCount, receivedCount = expectedCount) {
  if (!Number.isInteger(expectedCount) || expectedCount < 1 || expectedCount > 250) {
    throw new Error('PR commit count exceeds GitHub API limit; manual DCO audit required');
  }
  if (receivedCount !== expectedCount) {
    throw new Error('GitHub PR commit listing is incomplete; refusing DCO approval');
  }
}

export async function checkMilestoneCommits(event, repo, token) {
  const pr = event.pull_request;
  if (!pr || pr.base?.ref !== 'milestone-0.1.0' || !Number.isInteger(pr.number)) {
    throw new Error('Milestone pull request event is required');
  }
  const live = await githubJson(`repos/${repo}/pulls/${pr.number}`, token);
  if (live.head?.sha !== pr.head?.sha || live.base?.sha !== pr.base?.sha) {
    throw new Error('Pull request head or base changed during admission check');
  }
  assertCompleteCommitList(live.commits);
  const commits = await pullCommits(repo, pr.number, token);
  assertCompleteCommitList(live.commits, commits.length);
  const records = commits.map(({ sha, commit }) => ({
    sha,
    authorName: commit.author?.name,
    authorEmail: commit.author?.email,
    committerName: commit.committer?.name,
    committerEmail: commit.committer?.email,
    message: commit.message,
    verified: commit.verification?.verified === true,
  }));
  const directErrors = checkCommitSignoffs(records);
  if (directErrors.length === 0) return [];
  if (directErrors.every((error) => error.includes('signature is not verified'))) return directErrors;

  const firstPage = await githubJson(`repos/${repo}/compare/${pr.base.sha}...develop?per_page=100&page=1`, token);
  if (firstPage.total_commits > 250) {
    throw new Error('Develop sync exceeds GitHub compare limit; manual DCO audit required');
  }
  const trustedShas = new Set(firstPage.commits.map((commit) => commit.sha));
  for (let page = 2; trustedShas.size < firstPage.total_commits; page += 1) {
    const nextPage = await githubJson(`repos/${repo}/compare/${pr.base.sha}...develop?per_page=100&page=${page}`, token);
    if (nextPage.commits.length === 0) throw new Error('Develop comparison was truncated');
    for (const commit of nextPage.commits) trustedShas.add(commit.sha);
  }
  return checkCommitSignoffs(records, trustedShas);
}

if (process.argv[1]?.endsWith('/check-milestone-commits.mjs')) {
  try {
    const eventPath = process.env.GITHUB_EVENT_PATH;
    const repo = process.env.GITHUB_REPOSITORY;
    const token = process.env.GITHUB_TOKEN;
    if (!eventPath || !repo || !token) throw new Error('GitHub event, repository, and token are required');
    const event = JSON.parse(readFileSync(eventPath, 'utf8'));
    const errors = await checkMilestoneCommits(event, repo, token);
    for (const error of errors) console.error(error);
    if (errors.length > 0) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
