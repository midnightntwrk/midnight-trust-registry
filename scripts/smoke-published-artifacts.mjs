#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  packageManifestCatalog,
  publishWorkspaces,
} from "./trust-registry-workspace-catalog.mjs";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const parseArgs = () => {
  const options = {
    registry: "https://registry.npmjs.org",
    tarballDir: undefined,
    version: undefined,
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--registry":
        options.registry = args[++index];
        break;
      case "--tarball-dir":
        options.tarballDir = path.resolve(repoRoot, args[++index]);
        break;
      case "--version":
        options.version = args[++index];
        break;
      case "--help":
        console.log(
          [
            "Usage: node scripts/smoke-published-artifacts.mjs [options]",
            "",
            "Options:",
            "  --version <version>     Published package version to install from a registry.",
            "  --registry <url>        Registry URL. Defaults to https://registry.npmjs.org.",
            "  --tarball-dir <dir>     Use locally packed tarballs instead of a registry.",
          ].join("\n"),
        );
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!options.version && !options.tarballDir) {
    throw new Error("Either --version or --tarball-dir is required");
  }

  return options;
};

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });

  if (result.status !== 0) {
    throw new Error(
      [
        `${command} ${args.join(" ")} failed with exit code ${result.status}`,
        result.stdout,
        result.stderr,
      ]
        .filter(Boolean)
        .join("\n"),
    );
  }

  return result.stdout;
};

const locateTarball = (tarballDir, workspace) => {
  const packageName = packageManifestCatalog.get(workspace)?.name;
  if (!packageName) {
    throw new Error(`Missing package manifest catalog entry for ${workspace}`);
  }

  const packageSlug = packageName
    .replace(/^@/, "")
    .replaceAll("/", "-");
  const tarball = fs
    .readdirSync(tarballDir)
    .find((entry) => entry.startsWith(`${packageSlug}-`) && entry.endsWith(".tgz"));

  if (!tarball) {
    throw new Error(`Missing tarball for ${packageName} in ${tarballDir}`);
  }

  return path.join(tarballDir, tarball);
};

const installTargets = (options) => {
  if (options.tarballDir) {
    return publishWorkspaces.map((workspace) =>
      locateTarball(options.tarballDir, workspace)
    );
  }

  return publishWorkspaces.map((workspace) => {
    const packageName = packageManifestCatalog.get(workspace)?.name;
    if (!packageName) {
      throw new Error(`Missing package manifest catalog entry for ${workspace}`);
    }
    return `${packageName}@${options.version}`;
  });
};

const smokeImports = publishWorkspaces.flatMap((workspace) =>
  packageManifestCatalog.get(workspace)?.smokeImports ?? [],
);

const options = parseArgs();
const consumerRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "trust-registry-published-smoke-"),
);

try {
  fs.writeFileSync(
    path.join(consumerRoot, "package.json"),
    `${JSON.stringify({ name: "trust-registry-published-smoke", private: true, type: "module" }, null, 2)}\n`,
  );

  const installArgs = [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    ...installTargets(options),
  ];
  if (!options.tarballDir) {
    installArgs.push("--registry", options.registry);
  }

  run("npm", installArgs, {
    cwd: consumerRoot,
    env: {
      ...process.env,
      npm_config_registry: options.registry,
    },
  });

  fs.writeFileSync(
    path.join(consumerRoot, "smoke.mjs"),
    [
      `const imports = ${JSON.stringify(smokeImports, null, 2)};`,
      "for (const specifier of imports) {",
      "  await import(specifier);",
      "  console.log(`[smoke-published-artifacts] imported ${specifier}`);",
      "}",
    ].join("\n"),
  );

  run("node", ["smoke.mjs"], { cwd: consumerRoot });
} finally {
  fs.rmSync(consumerRoot, { force: true, recursive: true });
}

if (options.tarballDir) {
  console.log("[smoke-published-artifacts] Local release tarballs install and import cleanly.");
} else {
  console.log(
    `[smoke-published-artifacts] Published packages ${options.version} install and import cleanly from ${options.registry}.`,
  );
}
