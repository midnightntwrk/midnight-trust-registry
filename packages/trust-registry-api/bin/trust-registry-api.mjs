#!/usr/bin/env node

import { runTrustRegistryApiCli } from "../dist/cli.js";

runTrustRegistryApiCli().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
