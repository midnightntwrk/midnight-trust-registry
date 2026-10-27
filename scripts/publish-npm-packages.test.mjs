import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const publisher = join(root, "scripts/publish-npm-packages.sh");

const fakeNode = `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  scripts/release-candidate-manifest.mjs) exit 0 ;;
  scripts/trust-registry-workspace-catalog.mjs)
    printf 'catalog\\n' >> "$FAKE_LOG"
    if [[ "$FAKE_CATALOG" == failure ]]; then exit 17; fi
    if [[ "$FAKE_CATALOG" == populated ]]; then printf 'workspace-a\\n'; fi
    ;;
  --input-type=module)
    if [[ "$*" == *workspace-a* ]]; then printf '@example/a'; fi
    ;;
  -e) printf 'example-a-0.1.0.tgz' ;;
  scripts/check-publish-tarball.mjs) printf 'manifest-check\\n' >> "$FAKE_LOG" ;;
  scripts/check-published-package-integrity.mjs) exec "$REAL_NODE" "$@" ;;
  *) printf 'unexpected node call: %s\\n' "$1" >&2; exit 30 ;;
esac
`;

const fakeNpm = `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  view)
    printf 'view\\n' >> "$FAKE_LOG"
    case "$FAKE_NPM_VIEW" in
      existing) cat "$FAKE_NPM_DIST" ;;
      missing) printf 'npm error code E404\\n' >&2; exit 1 ;;
      failure) printf 'npm error code E503\\n' >&2; exit 1 ;;
    esac
    ;;
  publish) printf 'publish\\n' >> "$FAKE_LOG" ;;
  *) printf 'unexpected npm call: %s\\n' "$1" >&2; exit 30 ;;
esac
`;

// Stub registry I/O and catalog generation only; the published-byte integrity helper runs for real.
async function runPublisher({ catalog = "populated", lookup = "missing", integrityBytes } = {}) {
  const temp = await mkdtemp(join(tmpdir(), "tr-publish-runner-"));
  try {
    const bin = join(temp, "bin");
    const tarballDir = join(temp, "tarballs");
    await mkdir(bin);
    await mkdir(tarballDir);
    const tarball = Buffer.from("reviewed tarball bytes");
    await writeFile(join(tarballDir, "example-a-0.1.0.tgz"), tarball);
    await writeFile(join(temp, "manifest.json"), "{}\n");
    await writeFile(join(bin, "node"), fakeNode, { mode: 0o755 });
    await writeFile(join(bin, "npm"), fakeNpm, { mode: 0o755 });
    const digest = createHash("sha512").update(integrityBytes ?? tarball).digest("base64");
    await writeFile(join(temp, "dist.json"), JSON.stringify({ integrity: `sha512-${digest}` }));
    const result = spawnSync("bash", [publisher], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        REAL_NODE: process.execPath,
        FAKE_LOG: join(temp, "calls.log"),
        FAKE_CATALOG: catalog,
        FAKE_NPM_VIEW: lookup,
        FAKE_NPM_DIST: join(temp, "dist.json"),
        NODE_AUTH_TOKEN: "offline-test-only",
        VERSION: "0.1.0",
        MANIFEST_PATH: join(temp, "manifest.json"),
        TARBALL_DIR: tarballDir,
        REGISTRY: "https://registry.invalid",
      },
    });
    let calls = "";
    try { calls = await readFile(join(temp, "calls.log"), "utf8"); } catch { /* No calls. */ }
    return { result, calls: calls.trim().split("\n").filter(Boolean) };
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

test("catalog failure or empty catalog cannot succeed without publishing", async () => {
  for (const catalog of ["failure", "empty"]) {
    const { result, calls } = await runPublisher({ catalog });
    assert.notEqual(result.status, 0);
    assert.deepEqual(calls, ["catalog"]);
  }
});

test("a missing version publishes only after a manifest recheck", async () => {
  const { result, calls } = await runPublisher();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(calls, ["catalog", "view", "manifest-check", "publish"]);
});

test("an identical existing version is skipped after byte verification", async () => {
  const { result, calls } = await runPublisher({ lookup: "existing" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(calls, ["catalog", "view", "manifest-check"]);
  assert.match(result.stdout, /already exists with matching bytes/u);
});

test("changed registry bytes or an uncertain lookup fail closed", async () => {
  const changed = await runPublisher({ lookup: "existing", integrityBytes: Buffer.from("other bytes") });
  assert.notEqual(changed.result.status, 0);
  assert.deepEqual(changed.calls, ["catalog", "view", "manifest-check"]);
  assert.match(changed.result.stderr, /integrity differs/u);
  const uncertain = await runPublisher({ lookup: "failure" });
  assert.notEqual(uncertain.result.status, 0);
  assert.deepEqual(uncertain.calls, ["catalog", "view"]);
  assert.match(uncertain.result.stderr, /refusing publish/u);
});
