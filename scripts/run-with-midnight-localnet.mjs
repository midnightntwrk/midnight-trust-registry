#!/usr/bin/env node

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { checkLedger9LocalStack, localnetAttachFailure,
  localnetInputFromEnvironment } from "./check-ledger9-local-stack.mjs";

function runCommand(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", shell: false });
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (signal) reject(new Error(`Localnet command terminated by ${signal}`));
      else resolve(code ?? 1);
    });
  });
}

export async function runWithMidnightLocalnet(argv, dependencies = {}) {
  const args = argv[0] === "--" ? argv.slice(1) : argv;
  if (!args[0] || args[0].startsWith("-")) {
    throw new Error("Usage: pnpm localnet:run -- <command> [args...]");
  }
  try {
    await (dependencies.discover ?? checkLedger9LocalStack)(localnetInputFromEnvironment());
  } catch (error) {
    throw new Error(localnetAttachFailure(error), { cause: error });
  }
  return (dependencies.run ?? runCommand)(args[0], args.slice(1));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    process.exitCode = await runWithMidnightLocalnet(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
