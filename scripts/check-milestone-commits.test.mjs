import assert from 'node:assert/strict';
import test from 'node:test';
import { checkCommitSignoffs } from './check-milestone-commits.mjs';

const commit = {
  sha: 'a'.repeat(40),
  authorName: 'A Contributor',
  authorEmail: 'a@example.com',
  message: 'docs: explain harness\n\nSigned-off-by: A Contributor <a@example.com>',
};

test('accepts an author-matching DCO signoff', () => {
  assert.deepEqual(checkCommitSignoffs([commit]), []);
});

test('rejects absent and different-author signoffs', () => {
  assert.equal(checkCommitSignoffs([{ ...commit, message: 'docs: no signoff' }]).length, 1);
  assert.equal(checkCommitSignoffs([{ ...commit, message: 'Signed-off-by: Another <a@example.com>' }]).length, 1);
});

test('rejects an empty authored commit range', () => {
  assert.equal(checkCommitSignoffs([]).length, 1);
});

test('grandfathers a commit already present on develop for train sync', () => {
  assert.deepEqual(checkCommitSignoffs([{ ...commit, message: 'legacy commit' }], new Set([commit.sha])), []);
});
