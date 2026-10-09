import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import yaml from "js-yaml";

import { missingFullContractArtifacts, unexpectedLightContractArtifacts } from "./package-contents-policy.mjs";

test("light contract artifacts contain only generated contract modules", () => {
  const paths = [
    "dist/managed/trust-registry/contract/index.js",
    "dist/managed/trust-registry/contract/index.d.ts",
    "dist/trust-registry.compact",
    "dist/managed/trust-registry/keys/proposeIssuerAuthorization.prover",
    "dist/managed/trust-registry/keys/proposeIssuerAuthorization.verifier",
    "dist/managed/trust-registry/zkir/proposeIssuerAuthorization.zkir",
    "dist/managed/trust-registry/compiler/contract-info.json",
  ];
  assert.deepEqual(unexpectedLightContractArtifacts(paths, "trust-registry"), paths.slice(3));
});

test("full release artifacts require a proving key and ZK IR", () => {
  const complete = [
    "dist/managed/trust-registry/contract/index.js",
    "dist/managed/trust-registry/keys/proposeIssuerAuthorization.prover",
    "dist/managed/trust-registry/keys/proposeIssuerAuthorization.verifier",
    "dist/managed/trust-registry/zkir/proposeIssuerAuthorization.zkir",
  ];
  assert.deepEqual(missingFullContractArtifacts(complete, "trust-registry"), []);
  assert.deepEqual(missingFullContractArtifacts(complete.slice(0, 1), "trust-registry"), ["ZK IR", "proving keys", "verification keys"]);
  assert.deepEqual(missingFullContractArtifacts(complete.slice(0, 2), "trust-registry"), ["ZK IR", "verification keys", "ZK IR for proposeIssuerAuthorization", "verification key for proposeIssuerAuthorization"]);
  assert.deepEqual(missingFullContractArtifacts(complete, "another-contract"), ["ZK IR", "proving keys", "verification keys"]);
  assert.deepEqual(missingFullContractArtifacts([...complete, "dist/managed/trust-registry/zkir/activateIssuerAuthorization.zkir"], "trust-registry"), [
    "proving key for activateIssuerAuthorization",
    "verification key for activateIssuerAuthorization",
  ]);
});

test("publish workflow runs light tests before full build and package gate", () => {
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const workflow = yaml.load(readFileSync(path.join(root, ".github/workflows/publish.yml"), "utf8"));
  const commands = workflow.jobs.publish.steps.map((step) => step.run ?? "");
  const lightTest = commands.indexOf("pnpm run test:light");
  const fullBuild = commands.indexOf("pnpm run build");
  const fullGate = commands.indexOf("pnpm run packages:check-contents");
  const pack = commands.findIndex((command) => command.startsWith("pnpm run artifacts:pack"));
  assert.ok(lightTest >= 0 && lightTest < fullBuild && fullBuild < fullGate && fullGate < pack);
  assert.ok(commands.slice(fullBuild + 1, pack).every((command) =>
    !command.includes("build:light") && !command.includes("test:light")));
});
