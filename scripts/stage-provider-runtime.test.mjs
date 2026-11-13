import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { chmod, cp, link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { stageProviderRuntime } from "./stage-provider-runtime.mjs";
import { verifyInstalledProviderRuntime } from "./verify-installed-provider-runtime.mjs";

const HASH = "a".repeat(64);

function run(file, args, cwd) {
  if (file === "git" && args[0] === "verify-commit") return "";
  if (file === "pnpm" && args[0] === "install") {
    assert.deepEqual(args, ["install", "--frozen-lockfile", "--ignore-scripts",
      "--package-import-method=copy"]);
    assert.equal(JSON.parse(readFileSync(join(cwd, "packages/demo/package.json"), "utf8")).source, true);
    mkdirSync(join(cwd, "node_modules/demo-helper"), { recursive: true });
    writeFileSync(join(cwd, "node_modules/demo-helper/index.js"), "module.exports = 'approved';\n");
    return "";
  }
  return execFileSync(file, args, { cwd, encoding: "utf8" }).trim();
}

async function fixture(visit) {
  const base = await mkdtemp(join(tmpdir(), "tr-provider-stage-"));
  const repo = join(base, "source");
  const bundle = join(base, "bundle");
  const parent = join(base, "private");
  const destination = join(parent, "provider");
  await mkdir(join(repo, "packages/demo"), { recursive: true });
  await mkdir(join(repo, "scripts"));
  await mkdir(join(bundle, "packages"), { recursive: true });
  await mkdir(parent, { mode: 0o700 });
  await writeFile(join(repo, "package.json"), "{\"private\":true}\n");
  await writeFile(join(repo, "packages/demo/package.json"), "{\"name\":\"demo\",\"source\":true}\n");
  await writeFile(join(repo, "scripts/pack-keyless-contract.mjs"), "export const source = 'signed';\n");
  await writeFile(join(repo, ".gitignore"), "private.seed\n");
  run("git", ["init", "-q"], repo);
  run("git", ["add", "."], repo);
  run("git", ["-c", "commit.gpgsign=false", "-c", "user.name=Test",
    "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], repo);
  const revision = run("git", ["rev-parse", "HEAD"], repo);
  await writeFile(join(repo, "private.seed"), "must not be copied\n");
  const archiveRoot = join(base, "archive");
  await mkdir(join(archiveRoot, "package/dist"), { recursive: true });
  await writeFile(join(archiveRoot, "package/package.json"), "{\"name\":\"demo\",\"packed\":true}\n");
  await writeFile(join(archiveRoot, "package/dist/entry.js"), "export const installed = true;\n");
  const filename = "demo-0.1.0.tgz";
  run("tar", ["-czf", join(bundle, "packages", filename), "-C", archiveRoot, "package"], repo);
  const packageSha = createHash("sha256")
    .update(readFileSync(join(bundle, "packages", filename))).digest("hex");
  await writeManifest(bundle, revision, packageSha);
  const dependencies = { sourceRoot: repo, command: run, expectedWorkspaces: ["packages/demo"],
    requiredEntrypoints: ["package.json"],
    verifyBundle: async () => ({ sourceRevision: revision, inventorySha256: HASH,
      packageManifestSha256: manifestSha(bundle) }) };
  try {
    await visit({ repo, bundle, archiveRoot, parent, destination, revision, packageSha, dependencies });
  } finally {
    await chmod(parent, 0o700);
    await rm(base, { recursive: true, force: true });
  }
}

async function writeManifest(bundle, sourceRevision, packageSha) {
  await writeFile(join(bundle, "release-manifest.json"), JSON.stringify({ sourceRevision,
    packages: [{ workspace: "packages/demo", filename: "demo-0.1.0.tgz", sha256: packageSha }] }));
}

function manifestSha(bundle) {
  return createHash("sha256").update(readFileSync(join(bundle, "release-manifest.json"))).digest("hex");
}

test("stages only committed source and verified packages without promoting qualification", () => fixture(async ({
  bundle, destination, revision, dependencies,
}) => {
  const result = await stageProviderRuntime(bundle, destination, dependencies);
  assert.equal(result.sourceRevision, revision);
  assert.equal(result.ownership, "current-user-staging-only");
  assert.equal(result.releaseQualified, false);
  assert.equal(result.packageCount, 1);
  assert.match(result.contentSha256, /^[0-9a-f]{64}$/u);
  assert.match(await readFile(join(destination, "packages/demo/dist/entry.js"), "utf8"), /installed/u);
  assert.equal(JSON.parse(await readFile(join(destination, "packages/demo/package.json"), "utf8")).packed, true);
  await assert.rejects(readFile(join(destination, "private.seed")), { code: "ENOENT" });
  await assert.rejects(stageProviderRuntime(bundle, destination, dependencies), { code: "EEXIST" });
}));

for (const loadedImageKind of ["index", "config", "unrelated"]) test(`keyless provider staging ${loadedImageKind} image`, () => fixture(async ({
  repo, bundle, destination, revision, packageSha, dependencies,
}) => {
  const imageId = `sha256:${"b".repeat(64)}`;
  const configId = `sha256:${"d".repeat(64)}`;
  const loadedId = loadedImageKind === "index" ? imageId
    : loadedImageKind === "config" ? configId : `sha256:${"e".repeat(64)}`;
  await mkdir(join(bundle, "proof-params"));
  await mkdir(join(bundle, "keygen"));
  await writeFile(join(bundle, "keygen/zkir"), "pinned generator\n");
  await writeFile(join(bundle, "release-manifest.json"), JSON.stringify({ sourceRevision: revision,
    packages: [{ workspace: "contracts/trust-registry", filename: "demo-0.1.0.tgz",
      sha256: packageSha }] }));
  let regenerated = false;
  const command = (file, args, cwd) => {
    if (file === "docker" && args[0] === "image") {
      assert.deepEqual(args, ["image", "inspect", `tr-standalone/api:sha-${revision}`,
        "--format", "{{.Id}}"]);
      return loadedId;
    }
    if (file === "docker" && args[0] === "run") {
      writeFileSync(join(repo, "scripts/pack-keyless-contract.mjs"), "export const source = 'changed';\n");
      assert.equal(args[args.indexOf("--entrypoint") + 2], loadedId);
      assert.ok(args.includes("none"));
      assert.ok(args.includes("--read-only"));
      assert.ok(args.includes("HOME=/home/keygen"));
      assert.ok(args.some((arg) => arg.includes("dst=/home/keygen/.cache/midnight/zk-params,readonly")));
      assert.equal(args.at(-3), packageSha);
      assert.equal(args.at(-1), "1");
      const output = args.find((arg) => arg.includes("dst=/output"));
      const stage = output?.match(/^type=bind,src=(.+),dst=\/output$/u)?.[1];
      assert.ok(stage);
      assert.equal(args.find((arg) => arg.endsWith("dst=/scripts,readonly")),
        `type=bind,src=${join(realpathSync(destination), "scripts")},dst=/scripts,readonly`);
      assert.equal(readFileSync(join(destination, "scripts/pack-keyless-contract.mjs"), "utf8"),
        "export const source = 'signed';\n");
      assert.equal(args[args.indexOf("/scripts/pack-keyless-contract.mjs") + 2],
        "/output/demo-0.1.0.tgz");
      assert.equal(args[args.indexOf("/scripts/pack-keyless-contract.mjs") + 4],
        "/output/zkir");
      assert.equal(readFileSync(join(stage, "zkir"), "utf8"), "pinned generator\n");
      mkdirSync(join(stage, "materialized-contract", "dist/managed/trust-registry/keys"),
        { recursive: true });
      writeFileSync(join(stage, "materialized-contract/package.json"),
        "{\"name\":\"@midnight-ntwrk/trust-registry-contract\"}\n");
      writeFileSync(join(stage, "materialized-contract/dist/managed/trust-registry/keys/demo.prover"),
        "generated-and-checked\n");
      regenerated = true;
      return "";
    }
    return run(file, args, cwd);
  };
  const verified = { sourceRevision: revision, inventorySha256: HASH,
    packageManifestSha256: manifestSha(bundle),
    apiRuntime: { imageId, configId },
    keylessRuntime: { manifestSha256: "c".repeat(64), path: join(bundle, "keygen/zkir"),
      sha256: createHash("sha256").update("pinned generator\n").digest("hex") } };
  if (loadedImageKind === "unrelated") {
    await assert.rejects(stageProviderRuntime(bundle, destination, {
      ...dependencies, command, expectedWorkspaces: ["contracts/trust-registry"],
      verifyBundle: async () => verified,
    }), /differs from the verified install/u);
    assert.equal(regenerated, false);
    return;
  }
  const result = await stageProviderRuntime(bundle, destination, {
    ...dependencies, command, expectedWorkspaces: ["contracts/trust-registry"],
    verifyBundle: async () => verified,
  });
  assert.equal(regenerated, true);
  assert.equal(result.keygenImageId, loadedId);
  assert.equal(await readFile(join(destination,
    "contracts/trust-registry/dist/managed/trust-registry/keys/demo.prover"), "utf8"),
  "generated-and-checked\n");
}));

test("verifies a copied install against externally reviewed stage digests", () => fixture(async ({
  bundle, destination, parent, revision, dependencies,
}) => {
  const staged = await stageProviderRuntime(bundle, destination, dependencies);
  const installed = join(parent, "installed");
  await cp(destination, installed, { recursive: true });
  const expected = { sourceRevision: revision, inventorySha256: HASH,
    contentSha256: staged.contentSha256 };
  const options = { boundary: parent, trustedUid: process.getuid() };
  const verified = await verifyInstalledProviderRuntime(installed, expected, options);
  assert.equal(verified.contentSha256, staged.contentSha256);
  assert.equal(verified.releaseQualified, false);

  await writeFile(join(installed, "packages/demo/dist/entry.js"), "tampered\n");
  await assert.rejects(verifyInstalledProviderRuntime(installed, expected, options), /differs from the reviewed stage/u);
}));

test("rejects mutation of an installed transitive dependency", () => fixture(async ({
  bundle, destination, parent, revision, dependencies,
}) => {
  const staged = await stageProviderRuntime(bundle, destination, dependencies);
  const installed = join(parent, "installed");
  await cp(destination, installed, { recursive: true });
  const expected = { sourceRevision: revision, inventorySha256: HASH,
    contentSha256: staged.contentSha256 };
  const options = { boundary: parent, trustedUid: process.getuid() };
  await verifyInstalledProviderRuntime(installed, expected, options);
  await writeFile(join(installed, "node_modules/demo-helper/index.js"), "module.exports = 'changed';\n");
  await assert.rejects(verifyInstalledProviderRuntime(installed, expected, options),
    /differs from the reviewed stage/u);
}));

test("rejects a linked or oversized installed stage report", () => fixture(async ({
  bundle, destination, parent, revision, dependencies,
}) => {
  const staged = await stageProviderRuntime(bundle, destination, dependencies);
  const installed = join(parent, "installed");
  await cp(destination, installed, { recursive: true });
  const expected = { sourceRevision: revision, inventorySha256: HASH,
    contentSha256: staged.contentSha256 };
  const options = { boundary: parent, trustedUid: process.getuid() };
  const report = join(installed, "provider-stage.json");
  const original = await readFile(report);
  await rm(report);
  await symlink("package.json", report);
  await assert.rejects(verifyInstalledProviderRuntime(installed, expected, options));
  await rm(report);
  await writeFile(report, original);
  const alias = join(installed, "stage-report-link.json");
  await link(report, alias);
  await assert.rejects(verifyInstalledProviderRuntime(installed, expected, options),
    /non-regular or hard-linked entry|bounded single-link regular file/u);
  await rm(alias);
  await writeFile(report, Buffer.alloc(64 * 1024 + 1));
  await assert.rejects(verifyInstalledProviderRuntime(installed, expected, options),
    /bounded single-link regular file/u);
}));

test("rejects a substituted stage report even if installed files are unchanged", () => fixture(async ({
  bundle, destination, parent, dependencies,
}) => {
  const staged = await stageProviderRuntime(bundle, destination, dependencies);
  const installed = join(parent, "installed");
  await cp(destination, installed, { recursive: true });
  const reportPath = join(installed, "provider-stage.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  report.sourceRevision = "b".repeat(40);
  await writeFile(reportPath, JSON.stringify(report));
  await assert.rejects(verifyInstalledProviderRuntime(installed, {
    sourceRevision: staged.sourceRevision, inventorySha256: HASH,
    contentSha256: staged.contentSha256,
  }, { boundary: parent, trustedUid: process.getuid() }), /report differs/u);
}));

test("rejects source mismatch before creating a stage", () => fixture(async ({ bundle, destination,
  dependencies,
}) => {
  const changed = { ...dependencies,
    verifyBundle: async () => ({ ...await dependencies.verifyBundle(), sourceRevision: "b".repeat(40) }) };
  await assert.rejects(stageProviderRuntime(bundle, destination, changed), /does not match/u);
  await assert.rejects(readFile(join(destination, "provider-stage.json")), { code: "ENOENT" });
}));

test("rejects a missing install-inventory digest before creating a stage", () => fixture(async ({ bundle,
  destination, revision, dependencies,
}) => {
  await assert.rejects(stageProviderRuntime(bundle, destination, { ...dependencies,
    verifyBundle: async () => ({ sourceRevision: revision }),
  }), /does not match the signed source commit/u);
  await assert.rejects(readFile(join(destination, "provider-stage.json")), { code: "ENOENT" });
}));

test("rejects unexpected untracked source files but ignores private evidence", () => fixture(async ({ repo,
  bundle, destination, dependencies,
}) => {
  await writeFile(join(repo, "unexpected-runtime.mjs"), "export default true;\n");
  await assert.rejects(stageProviderRuntime(bundle, destination, dependencies), /clean signed source commit/u);
}));

test("rejects a non-private staging parent", () => fixture(async ({ bundle, parent, destination,
  dependencies,
}) => {
  await chmod(parent, 0o755);
  await assert.rejects(stageProviderRuntime(bundle, destination, dependencies), /private directory/u);
}));

test("rejects linked signed-source entries before creating a stage", () => fixture(async ({ repo,
  bundle, destination, dependencies,
}) => {
  await symlink("../private.seed", join(repo, "packages/demo/alias"));
  run("git", ["add", "packages/demo/alias"], repo);
  run("git", ["-c", "commit.gpgsign=false", "-c", "user.name=Test",
    "-c", "user.email=test@example.invalid", "commit", "-qm", "linked fixture"], repo);
  await assert.rejects(stageProviderRuntime(bundle, destination, dependencies), /unsafe archive entry/u);
  await assert.rejects(readFile(join(destination, "provider-stage.json")), { code: "ENOENT" });
}));

test("refuses staging inside the source checkout or verified bundle", () => fixture(async ({ repo,
  bundle, dependencies,
}) => {
  await assert.rejects(stageProviderRuntime(bundle, join(repo, "stage"), dependencies),
    /outside the source checkout and install bundle/u);
  await assert.rejects(stageProviderRuntime(bundle, join(bundle, "stage"), dependencies),
    /outside the source checkout and install bundle/u);
}));

test("rejects a required source file omitted by archive attributes", () => fixture(async ({ repo,
  bundle, destination, packageSha, dependencies,
}) => {
  await writeFile(join(repo, ".gitattributes"), "package.json export-ignore\n");
  run("git", ["add", ".gitattributes"], repo);
  run("git", ["-c", "commit.gpgsign=false", "-c", "user.name=Test",
    "-c", "user.email=test@example.invalid", "commit", "-qm", "archive fixture"], repo);
  const revision = run("git", ["rev-parse", "HEAD"], repo);
  await writeManifest(bundle, revision, packageSha);
  await assert.rejects(stageProviderRuntime(bundle, destination, { ...dependencies,
    verifyBundle: async () => ({ ...await dependencies.verifyBundle(), sourceRevision: revision }),
  }), /omitted files from the signed commit/u);
}));

test("rejects a non-entrypoint source file omitted by archive attributes", () => fixture(async ({ repo,
  bundle, destination, packageSha, dependencies,
}) => {
  await writeFile(join(repo, "packages/demo/helper.js"), "export const helper = true;\n");
  await writeFile(join(repo, ".gitattributes"), "packages/demo/helper.js export-ignore\n");
  run("git", ["add", ".gitattributes", "packages/demo/helper.js"], repo);
  run("git", ["-c", "commit.gpgsign=false", "-c", "user.name=Test",
    "-c", "user.email=test@example.invalid", "commit", "-qm", "partial archive fixture"], repo);
  const revision = run("git", ["rev-parse", "HEAD"], repo);
  await writeManifest(bundle, revision, packageSha);
  await assert.rejects(stageProviderRuntime(bundle, destination, { ...dependencies,
    verifyBundle: async () => ({ ...await dependencies.verifyBundle(), sourceRevision: revision }),
  }), /omitted files from the signed commit/u);
}));

test("rejects export-subst bytes that differ from the signed Git blob", () => fixture(async ({ repo,
  bundle, destination, packageSha, dependencies,
}) => {
  await writeFile(join(repo, "packages/demo/helper.js"), "export const revision = '$Format:%H$';\n");
  await writeFile(join(repo, ".gitattributes"), "packages/demo/helper.js export-subst\n");
  run("git", ["add", ".gitattributes", "packages/demo/helper.js"], repo);
  run("git", ["-c", "commit.gpgsign=false", "-c", "user.name=Test",
    "-c", "user.email=test@example.invalid", "commit", "-qm", "substituted archive fixture"], repo);
  const revision = run("git", ["rev-parse", "HEAD"], repo);
  await writeManifest(bundle, revision, packageSha);
  await assert.rejects(stageProviderRuntime(bundle, destination, { ...dependencies,
    verifyBundle: async () => ({ ...await dependencies.verifyBundle(), sourceRevision: revision }),
  }), /differs from the signed commit/u);
}));

test("rejects package bytes changed after bundle verification", () => fixture(async ({ bundle,
  destination, dependencies,
}) => {
  const archive = join(bundle, "packages/demo-0.1.0.tgz");
  await writeFile(archive, "not the approved package archive\n");
  await assert.rejects(stageProviderRuntime(bundle, destination, dependencies), /changed after bundle verification/u);
}));

test("rejects a same-revision manifest swap after bundle verification", () => fixture(async ({
  bundle, destination, revision, dependencies,
}) => {
  const verifyBundle = async () => {
    const verified = await dependencies.verifyBundle();
    await writeManifest(bundle, revision, "b".repeat(64));
    return verified;
  };
  await assert.rejects(stageProviderRuntime(bundle, destination, { ...dependencies, verifyBundle }),
    /Release manifest changed after bundle verification/u);
  await assert.rejects(readFile(join(destination, "provider-stage.json")), { code: "ENOENT" });
}));

test("rejects a package archive containing linked entries", () => fixture(async ({ repo,
  bundle, archiveRoot, destination, revision, dependencies,
}) => {
  await symlink("dist/entry.js", join(archiveRoot, "package/alias"));
  const archive = join(bundle, "packages/demo-0.1.0.tgz");
  run("tar", ["-czf", archive, "-C", archiveRoot, "package"], repo);
  const packageSha = createHash("sha256").update(readFileSync(archive)).digest("hex");
  await writeManifest(bundle, revision, packageSha);
  await assert.rejects(stageProviderRuntime(bundle, destination, dependencies), /non-regular archive entry/u);
}));
