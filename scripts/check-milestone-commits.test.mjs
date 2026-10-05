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

test('accepts a committer signoff but rejects an unrelated identity', () => {
  const committed = {
    ...commit,
    committerName: 'A Maintainer',
    committerEmail: 'maintainer@example.com',
    message: 'docs: explain harness\n\nSigned-off-by: A Maintainer <maintainer@example.com>',
  };
  assert.deepEqual(checkCommitSignoffs([committed]), []);
  assert.match(checkCommitSignoffs([{ ...committed, message: 'Signed-off-by: Other <other@example.com>' }]).join(' '), /DCO/);
});

test('rejects an unverified commit independently of its DCO trailer', () => {
  assert.match(checkCommitSignoffs([{ ...commit, verified: false }]).join(' '), /signature/);
});

test('rejects an empty authored commit range', () => {
  assert.equal(checkCommitSignoffs([]).length, 1);
});

test('grandfathers a commit already present on develop for train sync', () => {
  assert.deepEqual(checkCommitSignoffs([{ ...commit, message: 'legacy commit' }], new Set([commit.sha])), []);
});
