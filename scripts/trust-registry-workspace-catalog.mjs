#!/usr/bin/env node

import { stdout } from "node:process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const artifactDirectory = "artifacts/npm";
export const repositoryUrl =
  "git+https://github.com/midnightntwrk/midnight-trust-registry.git";

export const workspaceCatalog = [
  {
    workspace: "contracts/trust-registry",
    artifactPackage: true,
    publishPackage: true,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-contract",
      files: [
        "dist/**",
        "src/**/*.compact",
        "README.md",
        "scripts/*.mjs",
        "package.json",
        "tsconfig.json",
        "tsconfig.build.json",
      ],
      exports: [
        ".",
        "./contract",
        "./signing",
        "./testing",
        "./managed/trust-registry/contract/index.js",
      ],
      requiredPackedPaths: [
        "README.md",
        "package.json",
        "src/trust-registry.compact",
        "dist/index.js",
        "dist/contract.js",
        "dist/signing.js",
        "dist/testing.js",
        "dist/managed/trust-registry/contract/index.js",
      ],
      smokeImports: [
        "@midnight-ntwrk/trust-registry-contract",
        "@midnight-ntwrk/trust-registry-contract/contract",
        "@midnight-ntwrk/trust-registry-contract/signing",
        "@midnight-ntwrk/trust-registry-contract/testing",
        "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js",
      ],
    },
  },
  {
    workspace: "packages/trust-registry-domain",
    artifactPackage: true,
    publishPackage: true,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-domain",
      files: ["dist/**", "README.md"],
      exports: ["."],
      requiredPackedPaths: ["README.md", "package.json", "dist/index.js"],
      smokeImports: ["@midnight-ntwrk/trust-registry-domain"],
    },
  },
  {
    workspace: "packages/trust-registry-client",
    artifactPackage: true,
    publishPackage: true,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-client",
      files: ["dist/**", "README.md"],
      exports: ["."],
      requiredPackedPaths: ["README.md", "package.json", "dist/index.js"],
      smokeImports: ["@midnight-ntwrk/trust-registry-client"],
    },
  },
  {
    workspace: "packages/trust-registry-integration",
    artifactPackage: true,
    publishPackage: false,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-integration",
      files: ["dist/**", "README.md"],
      exports: ["."],
      requiredPackedPaths: ["README.md", "package.json", "dist/index.js"],
      smokeImports: ["@midnight-ntwrk/trust-registry-integration"],
    },
  },
  {
    workspace: "packages/trust-registry-cli",
    artifactPackage: true,
    publishPackage: false,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-cli",
      files: ["bin/trust-registry.mjs", "dist/**", "README.md"],
      exports: [".", "./cli"],
      bin: ["trust-registry"],
      requiredPackedPaths: [
        "README.md",
        "package.json",
        "bin/trust-registry.mjs",
        "dist/index.js",
        "dist/cli.js",
      ],
      smokeImports: [
        "@midnight-ntwrk/trust-registry-cli",
        "@midnight-ntwrk/trust-registry-cli/cli",
      ],
    },
  },
  {
    workspace: "adapters/trqp",
    artifactPackage: true,
    publishPackage: true,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-trqp-adapter",
      files: ["dist/**", "README.md"],
      exports: ["."],
      requiredPackedPaths: ["README.md", "package.json", "dist/index.js"],
      smokeImports: ["@midnight-ntwrk/trust-registry-trqp-adapter"],
    },
  },
  {
    workspace: "packages/trust-registry-api",
    artifactPackage: true,
    publishPackage: false,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-api",
      files: ["bin/trust-registry-api.mjs", "dist/**", "README.md"],
      exports: [".", "./cli", "./server"],
      bin: ["trust-registry-api"],
      requiredPackedPaths: [
        "README.md",
        "package.json",
        "bin/trust-registry-api.mjs",
        "dist/index.js",
        "dist/cli.js",
        "dist/server.js",
      ],
      smokeImports: [
        "@midnight-ntwrk/trust-registry-api",
        "@midnight-ntwrk/trust-registry-api/cli",
        "@midnight-ntwrk/trust-registry-api/server",
      ],
    },
  },
  {
    workspace: "adapters/openid-federation",
    artifactPackage: true,
    publishPackage: true,
    manifest: {
      name: "@midnight-ntwrk/trust-registry-openid-federation-adapter",
      files: ["dist/**", "README.md"],
      exports: ["."],
      requiredPackedPaths: ["README.md", "package.json", "dist/index.js"],
      smokeImports: ["@midnight-ntwrk/trust-registry-openid-federation-adapter"],
    },
  },
  {
    workspace: "packages/trust-registry-admin-console",
    artifactPackage: false,
    publishPackage: false,
  },
  {
    workspace: "packages/trust-registry-applicant-portal",
    artifactPackage: false,
    publishPackage: false,
  },
];

export const expectedWorkspaces = ["contracts/*", "packages/*", "adapters/*"];

export const artifactWorkspaces = workspaceCatalog
  .filter(({ artifactPackage }) => artifactPackage)
  .map(({ workspace }) => workspace);

export const publishWorkspaces = workspaceCatalog
  .filter(({ publishPackage }) => publishPackage)
  .map(({ workspace }) => workspace);

export const localOnlyArtifactWorkspaces = workspaceCatalog
  .filter(({ artifactPackage, publishPackage }) => artifactPackage && !publishPackage)
  .map(({ workspace }) => workspace);

export const packageManifestCatalog = new Map(
  workspaceCatalog
    .filter(({ artifactPackage }) => artifactPackage)
    .map(({ workspace, manifest }) => [workspace, manifest]),
);

const isDirectExecution =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
const [command] = process.argv.slice(2);

if (isDirectExecution) {
  switch (command) {
    case "--artifact-workspaces":
      stdout.write(`${artifactWorkspaces.join("\n")}\n`);
      break;
    case "--publish-workspaces":
      stdout.write(`${publishWorkspaces.join("\n")}\n`);
      break;
    case "--package-names":
      stdout.write(
        `${publishWorkspaces
          .map((workspace) => packageManifestCatalog.get(workspace)?.name ?? "")
          .filter(Boolean)
          .join("\n")}\n`,
      );
      break;
    case undefined:
    case "--help":
      stdout.write(
        [
          "Usage: node scripts/trust-registry-workspace-catalog.mjs <command>",
          "",
          "Commands:",
          "  --artifact-workspaces  Print artifact workspaces.",
          "  --publish-workspaces   Print artifact workspaces in pack/smoke order.",
          "  --package-names        Print artifact package names in pack/smoke order.",
        ].join("\n"),
      );
      stdout.write("\n");
      break;
    default:
      console.error(`[trust-registry-workspace-catalog] Unknown command: ${command}`);
      process.exit(2);
  }
}
