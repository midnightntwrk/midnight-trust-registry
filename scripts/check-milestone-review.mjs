import { readFileSync } from 'node:fs';

const RECEIPT = /^ {0,3}<!-- tr-review:v1 head=([0-9a-fA-F]{40}) mode=(self|external) round=([1-3]) verdict=pass -->[ \t]*$/;
const ISSUE_LINK = /\b(?:close[ds]?|fix(?:es|ed)?|resolve[ds]?|refs?|references)\s+#([1-9][0-9]*)\b/i;
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})/;

export function scanMilestoneBody(body) {
  const visible = [];
  const findings = [];
  const receipts = [];
  let fence = null;
  let inComment = false;
  let inFindings = false;

  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (fence !== null) {
      const close = fence.character === '`' ? /^ {0,3}`{3,}\s*$/ : /^ {0,3}~{3,}\s*$/;
      if (close.test(line) && trimmed[0] === fence.character && trimmed.length >= fence.length) {
        fence = null;
      } else if (inFindings) {
        findings.push(line);
      }
      continue;
    }

    if (!inComment) {
      const opening = line.match(FENCE_OPEN)?.[1];
      if (opening !== undefined) {
        fence = { character: opening[0], length: opening.length };
        continue;
      }
      if (/^ {4}|^\t/.test(line)) continue;
      if (RECEIPT.test(line)) {
        receipts.push(line.match(RECEIPT));
        continue;
      }
    }

    let prose = '';
    for (let index = 0; index < line.length;) {
      if (inComment) {
        const end = line.indexOf('-->', index);
        if (end === -1) break;
        inComment = false;
        index = end + 3;
      } else {
        const start = line.indexOf('<!--', index);
        if (start === -1) {
          prose += line.slice(index);
          break;
        }
        prose += line.slice(index, start);
        inComment = true;
        index = start + 4;
      }
    }

    if (/^##\s+Review findings\s*$/i.test(prose.trim())) {
      inFindings = true;
      continue;
    }
    if (/^##\s+/.test(prose.trim())) inFindings = false;
    visible.push(prose);
    if (inFindings) findings.push(prose);
  }

  return { visible: visible.join('\n'), findings: findings.join('\n'), receipts };
}

export function checkMilestoneReview(pr) {
  const errors = [];
  if (pr.base?.ref !== 'milestone-0.1.0') {
    errors.push('PR must target milestone-0.1.0');
  }
  const { visible, findings, receipts } = scanMilestoneBody(pr.body ?? '');
  if (!ISSUE_LINK.test(visible)) {
    errors.push('PR body must link an issue with a closing keyword or Refs #N');
  }
  if (receipts.length !== 1 || receipts[0][1].toLowerCase() !== pr.head?.sha) {
    errors.push('PR body must contain exactly one passing review receipt for the current head SHA');
  }
  const substantiveFindings = findings.trim();
  if (!substantiveFindings) {
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
