import { performance } from "node:perf_hooks";

const count = 10_000;
const iterations = 5_000;
const keys = Array.from({ length: count }, (_, index) =>
  `0x${index.toString(16).padStart(64, "0")}`);
const retained = Object.fromEntries(keys.map((key) => [key, "2026-10-10T00:05:00.000Z"]));
const target = keys.at(-1);
if (target === undefined) throw new Error("No nonce key to measure");

const measure = (lookup) => {
  const started = performance.now();
  for (let index = 0; index < iterations; index += 1) {
    if (!lookup()) throw new Error("Nonce lookup failed");
  }
  return Math.round((performance.now() - started) * 100) / 100;
};

process.stdout.write(`${JSON.stringify({
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  liveEntries: count,
  lookups: iterations,
  keyedMs: measure(() => retained[target] !== undefined),
  linearMs: measure(() => keys.includes(target)),
})}\n`);
