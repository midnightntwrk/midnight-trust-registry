import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const managed = join(root, "contracts/trust-registry/src/managed/trust-registry");
const manifestName = "zkir-key-manifest.json";
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const fileHash = (path) => sha256(readFileSync(path));

export const findZkirBinary = (pin, compactDirectory = process.env.COMPACT_DIRECTORY ?? join(homedir(), ".compact")) => {
  const versionDirectory = join(compactDirectory, "versions", pin);
  const binaries = readdirSync(versionDirectory)
    .map((target) => join(versionDirectory, target, "zkir"))
    .filter((path) => existsSync(path));
  if (binaries.length !== 1) throw new Error(`Expected one pinned zkir binary in ${versionDirectory}`);
  return binaries[0];
};

const readManifest = (path) => {
  try {
    const value = JSON.parse(readFileSync(path, "utf8"));
    return value?.version === 1 && value.circuits !== null && typeof value.circuits === "object"
      ? value : null;
  } catch {
    return null;
  }
};

const validPair = (keyDir, name, entry, zkirHash) => {
  if (entry?.zkirHash !== zkirHash) return false;
  const prover = join(keyDir, `${name}.prover`);
  const verifier = join(keyDir, `${name}.verifier`);
  try {
    return existsSync(prover) && existsSync(verifier)
      && statSync(prover).size > 0 && statSync(verifier).size > 0
      && fileHash(prover) === entry.proverHash && fileHash(verifier) === entry.verifierHash;
  } catch {
    return false;
  }
};

export function synchronizeProvingKeys({
  zkirDir,
  keyDir,
  distKeyDir,
  compactVersion,
  zkirVersion,
  compile,
  shardIndex,
  shardCount,
}) {
  const allCircuits = readdirSync(zkirDir).filter((name) => /^[A-Za-z][A-Za-z0-9_]*\.zkir$/u.test(name)).sort();
  if (allCircuits.length === 0) throw new Error("No generated ZKIR circuits to compile");
  if ((shardIndex === undefined) !== (shardCount === undefined)
    || (shardCount !== undefined && (!Number.isInteger(shardCount) || shardCount < 1
      || !Number.isInteger(shardIndex) || shardIndex < 0 || shardIndex >= shardCount))) {
    throw new Error("Invalid proving-key shard");
  }
  const circuits = shardCount === undefined ? allCircuits
    : allCircuits.filter((_, index) => index % shardCount === shardIndex);
  if (circuits.length === 0) throw new Error("Proving-key shard has no ZKIR circuits");
  mkdirSync(keyDir, { recursive: true });
  const previous = readManifest(join(keyDir, manifestName));
  const compatible = previous?.compactVersion === compactVersion && previous?.zkirVersion === zkirVersion;
  const next = { version: 1, compactVersion, zkirVersion, circuits: {} };
  let generated = 0;

  for (const file of circuits) {
    const name = file.slice(0, -".zkir".length);
    const zkirPath = join(zkirDir, file);
    const zkirHash = fileHash(zkirPath);
    if (!compatible || !validPair(keyDir, name, previous.circuits[name], zkirHash)) {
      const temporary = join(keyDir, `.zkir-${randomUUID()}`);
      try {
        compile(zkirPath, `${temporary}.prover`, `${temporary}.verifier`);
        if (!existsSync(`${temporary}.prover`) || !existsSync(`${temporary}.verifier`)
          || statSync(`${temporary}.prover`).size === 0 || statSync(`${temporary}.verifier`).size === 0) {
          throw new Error(`zkir produced incomplete keys for ${file}`);
        }
        renameSync(`${temporary}.prover`, join(keyDir, `${name}.prover`));
        renameSync(`${temporary}.verifier`, join(keyDir, `${name}.verifier`));
        generated += 1;
      } finally {
        rmSync(`${temporary}.prover`, { force: true });
        rmSync(`${temporary}.verifier`, { force: true });
      }
    }
    next.circuits[name] = {
      zkirHash,
      proverHash: fileHash(join(keyDir, `${name}.prover`)),
      verifierHash: fileHash(join(keyDir, `${name}.verifier`)),
    };
  }

  const names = new Set(circuits.map((file) => file.slice(0, -".zkir".length)));
  for (const file of readdirSync(keyDir)) {
    const match = /^([A-Za-z][A-Za-z0-9_]*)\.(?:prover|verifier)$/u.exec(file);
    if (match && !names.has(match[1])) rmSync(join(keyDir, file));
  }
  const manifestPath = join(keyDir, manifestName);
  const temporaryManifest = `${manifestPath}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporaryManifest, `${JSON.stringify(next)}\n`);
    renameSync(temporaryManifest, manifestPath);
  } finally {
    rmSync(temporaryManifest, { force: true });
  }
  if (distKeyDir) {
    rmSync(distKeyDir, { recursive: true, force: true });
    cpSync(keyDir, distKeyDir, { recursive: true });
  }
  return { total: circuits.length, reused: circuits.length - generated, generated };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  if (args.length !== 0 && (args.length !== 2 || args.some((value) => !/^\d+$/u.test(value)))) {
    throw new Error("Usage: proving-key-cache.mjs [shard-index shard-count]");
  }
  const shardIndex = args.length === 2 ? Number(args[0]) : undefined;
  const shardCount = args.length === 2 ? Number(args[1]) : undefined;
  const compactVersion = readFileSync(join(root, ".compact-version"), "utf8").trim();
  const zkir = findZkirBinary(compactVersion);
  const zkirVersion = execFileSync(zkir, ["--version"], { encoding: "utf8" }).trim();
  const result = synchronizeProvingKeys({
    zkirDir: join(managed, "zkir"),
    keyDir: shardCount === undefined ? join(managed, "keys")
      : join(managed, "sharded-keys", String(shardCount), String(shardIndex)),
    distKeyDir: shardCount === undefined
      ? join(root, "contracts/trust-registry/dist/managed/trust-registry/keys") : undefined,
    compactVersion,
    zkirVersion,
    shardIndex,
    shardCount,
    compile: (input, prover, verifier) => execFileSync(zkir, ["compile", input, prover, verifier], { stdio: "inherit" }),
  });
  process.stdout.write(`ZKIR keys: ${result.reused} reused, ${result.generated} generated, ${result.total} total\n`);
}
