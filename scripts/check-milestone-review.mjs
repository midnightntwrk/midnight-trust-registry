import { readFileSync } from 'node:fs';

const REVIEW_LINE = /^<!-- tr-review:v1 head=([0-9a-f]{40}) mode=(self|external) verdict=pass -->$/gm;
const ISSUE_LINK = /\b(?:Closes|Fixes|Refs)\s+#([1-9][0-9]*)\b/i;

export function checkMilestoneReview(pr) {
  const errors = [];
  if (pr.base?.ref !== 'milestone-0.1.0') {
    errors.push('PR must target milestone-0.1.0');
  }
  const body = pr.body ?? '';
  if (!ISSUE_LINK.test(body)) {
    errors.push('PR body must link an issue with Closes, Fixes, or Refs #N');
  }
  const receipts = [...body.matchAll(REVIEW_LINE)];
  if (receipts.length !== 1 || receipts[0][1] !== pr.head?.sha) {
    errors.push('PR body must contain exactly one passing review receipt for the current head SHA');
  }
  const findings = body.match(/^## Review findings\s*\n([\s\S]*?)(?=^## |$(?![\s\S]))/m)?.[1]
    ?.replace(/<!--[\s\S]*?-->/g, '').trim();
  if (!findings) {
    errors.push('PR body must include nonempty Review findings and disposition');
  }
  return errors;
}

if (process.argv[1]?.endsWith('/check-milestone-review.mjs')) {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) {
    console.error('GITHUB_EVENT_PATH is required');
    process.exitCode = 1;
  } else {
    const event = JSON.parse(readFileSync(eventPath, 'utf8'));
    const errors = checkMilestoneReview(event.pull_request ?? {});
    for (const error of errors) console.error(error);
    if (errors.length > 0) process.exitCode = 1;
  }
}
