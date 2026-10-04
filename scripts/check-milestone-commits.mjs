import { execFileSync } from 'node:child_process';

export function checkCommitSignoffs(commits, trustedShas = new Set()) {
  const errors = [];
  for (const { sha, authorName, authorEmail, message } of commits) {
    if (trustedShas.has(sha)) continue;
    const expected = `Signed-off-by: ${authorName} <${authorEmail}>`;
    if (!message.split('\n').some((line) => line.trim() === expected)) {
      errors.push(`${sha}: missing author-matching DCO signoff`);
    }
  }
  if (commits.length === 0) errors.push('PR contains no authored commits');
  return errors;
}

if (process.argv[1]?.endsWith('/check-milestone-commits.mjs')) {
  const log = execFileSync('git', [
    'log', '--no-merges', '--format=%H%x00%an%x00%ae%x00%B%x00',
    'HEAD^1..HEAD^2',
  ], { encoding: 'utf8' });
  const records = log.trimEnd().split('\0\n').filter(Boolean);
  const commits = records.map((record) => {
    const [sha, authorName, authorEmail, message] = record.split('\0');
    return { sha, authorName, authorEmail, message };
  });
  const trustedShas = new Set(execFileSync('git', [
    'rev-list', 'origin/develop',
  ], { encoding: 'utf8' }).trim().split('\n'));
  const errors = checkCommitSignoffs(commits, trustedShas);
  for (const error of errors) console.error(error);
  if (errors.length > 0) process.exitCode = 1;
}
