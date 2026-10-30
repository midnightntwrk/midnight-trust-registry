import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const source = dirname(fileURLToPath(import.meta.url));
const contract = "contracts/trust-registry";

test("documented demo and browser aliases never select destructive light builds", () => {
  const scripts = JSON.parse(readFileSync(join(source, "../package.json"), "utf8")).scripts;
  for (const name of ["test:e2e:demo", "test:e2e:demo:browser", "test:browser", "demo:signed",
    "demo:signed-issuer", "demo:signed-verifier", "demo:signed-auditor", "demo:signed-maintainer",
    "demo:governed", "demo:auditor", "demo:auditor:smoke"]) {
    assert.doesNotMatch(scripts[name], /build:light|integration:light/u, name);
  }
  for (const name of ["test:e2e:demo", "test:browser", "demo:signed", "demo:governed",
    "demo:auditor", "demo:auditor:smoke"]) {
    assert.match(scripts[name], /^bash scripts\/build-prebuilt-runtime\.sh && /u, name);
  }
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "tr-prebuilt-e2e-"));
  const script = join(root, "scripts/build-prebuilt-runtime.sh");
  const log = join(root, "pnpm.log");
  const bin = join(root, "bin");
  mkdirSync(dirname(script), { recursive: true });
  mkdirSync(bin);
  copyFileSync(join(source, "build-prebuilt-runtime.sh"), script);
  const sourceFile = join(root, contract, "src/trust-registry.compact");
  const distFile = join(root, contract, "dist/trust-registry.compact");
  const managedFile = join(root, contract, "dist/managed/trust-registry/contract/index.js");
  const sourceManagedFile = join(root, contract, "src/managed/trust-registry/contract/index.js");
  const sourceManagedDeclaration = join(root, contract, "src/managed/trust-registry/contract/index.d.ts");
  const distManagedDeclaration = join(root, contract, "dist/managed/trust-registry/contract/index.d.ts");
  for (const file of [sourceFile, distFile, managedFile]) mkdirSync(dirname(file), { recursive: true });
  writeFileSync(sourceFile, "pragma language_version >= 0.20.0;\n");
  writeFileSync(distFile, readFileSync(sourceFile));
  writeFileSync(managedFile, "// fixture\n");
  writeFileSync(distManagedDeclaration, "export declare const fixture: true;\n");
  const fakePnpm = join(bin, "pnpm");
  writeFileSync(fakePnpm, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_PNPM_LOG\"\nexit \"${FAKE_PNPM_EXIT:-0}\"\n");
  chmodSync(fakePnpm, 0o755);
  const run = (extraEnv = {}) => spawnSync("bash", [script], { encoding: "utf8", env: {
    ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_PNPM_LOG: log, ...extraEnv,
  } });
  return { root, sourceFile, distFile, managedFile, sourceManagedFile, sourceManagedDeclaration,
    distManagedDeclaration, log, run };
}

test("demo E2E rebuilds current workspaces without a destructive Compact build", () => {
  const f = fixture();
  try {
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(f.sourceManagedFile, "utf8"), readFileSync(f.managedFile, "utf8"));
    assert.equal(readFileSync(f.sourceManagedDeclaration, "utf8"), readFileSync(f.distManagedDeclaration, "utf8"));
    const calls = readFileSync(f.log, "utf8").trim().split("\n");
    assert.equal(calls.length, 2);
    assert.equal(calls[0], "--filter @midnight-ntwrk/trust-registry-contract exec tsc -p tsconfig.build.json");
    assert.match(calls[1], /^-r --filter @midnight-ntwrk\/trust-registry-domain /u);
    assert.match(calls[1], /--filter @midnight-ntwrk\/trust-registry-api /u);
    assert.match(calls[1], /--filter @midnight-ntwrk\/trust-registry-applicant-portal /u);
    assert.match(calls[1], /--filter @midnight-ntwrk\/trust-registry-trqp-adapter /u);
    assert.match(calls[1], / run build$/u);
    assert.doesNotMatch(calls.join(" "), /build:light|compact:light|clean/u);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("demo E2E restores missing declarations without replacing generated source", () => {
  const f = fixture();
  try {
    mkdirSync(dirname(f.sourceManagedFile), { recursive: true });
    writeFileSync(f.sourceManagedFile, readFileSync(f.managedFile));
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(f.sourceManagedDeclaration, "utf8"), readFileSync(f.distManagedDeclaration, "utf8"));
    assert.equal(readFileSync(f.sourceManagedFile, "utf8"), readFileSync(f.managedFile, "utf8"));
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("demo E2E refuses generated source that differs from preserved dist", () => {
  const f = fixture();
  try {
    mkdirSync(dirname(f.sourceManagedFile), { recursive: true });
    writeFileSync(f.sourceManagedFile, "// stale generated module\n");
    assert.notEqual(f.run().status, 0);
    assert.throws(() => readFileSync(f.log), /ENOENT/u);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("demo E2E refuses missing or stale Compact output before starting a build", () => {
  const f = fixture();
  try {
    writeFileSync(f.distFile, "different contract\n");
    assert.notEqual(f.run().status, 0);
    assert.throws(() => readFileSync(f.log), /ENOENT/u);
    writeFileSync(f.distFile, readFileSync(f.sourceFile));
    rmSync(f.managedFile);
    assert.notEqual(f.run().status, 0);
    assert.throws(() => readFileSync(f.log), /ENOENT/u);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("demo E2E propagates a package build failure", () => {
  const f = fixture();
  try {
    assert.equal(f.run({ FAKE_PNPM_EXIT: "17" }).status, 17);
    assert.equal(readFileSync(f.log, "utf8").trim().split("\n").length, 1);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});
