import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { checkMilestoneReview } from './check-milestone-review.mjs';

const head = 'a'.repeat(40);
const valid = {
  base: { ref: 'milestone-0.1.0' },
  head: { sha: head },
  body: `Closes #42\n\n## Review findings\nNo blocking findings after self-review.\n\n<!-- tr-review:v1 head=${head} mode=self verdict=pass -->`,
};

test('accepts current-head self-review receipt', () => {
  assert.deepEqual(checkMilestoneReview(valid), []);
});

test('accepts current-head external-review receipt', () => {
  assert.deepEqual(checkMilestoneReview({ ...valid, body: valid.body.replace('mode=self', 'mode=external') }), []);
});

test('rejects stale and duplicate receipts', () => {
  assert.match(checkMilestoneReview({ ...valid, head: { sha: 'b'.repeat(40) } }).join(' '), /current head/);
  assert.match(checkMilestoneReview({ ...valid, body: `${valid.body}\n${valid.body.match(/<!-- tr-review[^\n]+/)[0]}` }).join(' '), /exactly one/);
});

test('rejects wrong target, missing issue, and missing findings', () => {
  const errors = checkMilestoneReview({ ...valid, base: { ref: 'develop' }, body: `## Review findings\n\n<!-- tr-review:v1 head=${head} mode=self verdict=pass -->` });
  assert.equal(errors.length, 3);
});

test('rejects an untouched template comment containing angle brackets', () => {
  const body = `Closes #42\n\n## Review findings\n<!-- Replace <placeholder> with findings. -->\n\n<!-- tr-review:v1 head=${head} mode=self verdict=pass -->`;
  assert.match(checkMilestoneReview({ ...valid, body }).join(' '), /nonempty Review findings/);
});

test('rejects issue links hidden in comments or code fences', () => {
  const body = `<!-- Closes #42 -->\n\n## Review findings\nNo blockers.\n\n<!-- tr-review:v1 head=${head} mode=self verdict=pass -->`;
  assert.match(checkMilestoneReview({ ...valid, body }).join(' '), /link an issue/);
  assert.match(checkMilestoneReview({ ...valid, body: body.replace('<!-- Closes #42 -->', '```text\nCloses #42\n```') }).join(' '), /link an issue/);
});

test('does not treat the repository PR template as completed findings', () => {
  const template = readFileSync(new URL('../.github/pull_request_template.md', import.meta.url), 'utf8');
  assert.match(checkMilestoneReview({ ...valid, body: template }).join(' '), /nonempty Review findings/);
});
