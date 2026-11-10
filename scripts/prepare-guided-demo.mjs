import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "contracts/trust-registry/src/trust-registry.compact");
const dist = resolve(root, "contracts/trust-registry/dist/trust-registry.compact");
const distDirectory = resolve(root, "contracts/trust-registry/dist");

const run = (command, args) => {
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
};

if (existsSync(dist)) {
  if (!readFileSync(source).equals(readFileSync(dist))) {
    process.stderr.write("Prebuilt Compact contract differs from current source. Prepare a source-matched build in a disposable checkout.\n");
    process.exit(1);
  }
} else if (existsSync(distDirectory)) {
  process.stderr.write("Incomplete prebuilt Compact output found. Inspect it before retrying the guided demo.\n");
  process.exit(1);
} else {
  process.stdout.write("First run: compiling the Compact contract. This may take several minutes; later starts reuse it.\n");
  run("pnpm", ["--filter", "@midnight-ntwrk/trust-registry-contract", "run", "build"]);
}

run("bash", ["scripts/build-prebuilt-runtime.sh"]);
