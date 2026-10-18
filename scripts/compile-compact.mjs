import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pin = readFileSync(resolve(root, ".compact-version"), "utf8");
if (!/^\d+\.\d+\.\d+\n$/.test(pin)) {
  throw new Error(".compact-version must contain one stable semver and a newline");
}

const result = spawnSync("compact", ["compile", `+${pin.trim()}`, ...process.argv.slice(2)], {
  stdio: "inherit",
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
