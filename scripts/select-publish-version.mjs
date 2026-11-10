#!/usr/bin/env node

import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

export function selectPublishVersion(value) {
  if (typeof value !== "string" || !/^0\.1\.0-rc[1-9][0-9]*$/u.test(value)) {
    throw new Error("Package publication requires a committed 0.1.0-rcN version");
  }
  return value;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length > 3 || (process.argv[2] !== undefined
      && process.argv[2] !== "--github-output")) {
      throw new Error("Usage: select-publish-version.mjs [--github-output]");
    }
    const version = selectPublishVersion(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version);
    if (process.argv[2] === "--github-output") {
      if (!process.env.GITHUB_OUTPUT) throw new Error("GITHUB_OUTPUT is required");
      appendFileSync(process.env.GITHUB_OUTPUT, `version=${version}\n`, { encoding: "utf8" });
    } else {
      process.stdout.write(`${version}\n`);
    }
  } catch (error) {
    console.error(`Publish version selection failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
