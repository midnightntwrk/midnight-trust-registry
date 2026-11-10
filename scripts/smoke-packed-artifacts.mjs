#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  artifactDirectory,
  artifactWorkspaces,
  packageManifestCatalog,
} from "./trust-registry-workspace-catalog.mjs";
import { verifyReleaseCandidateArtifacts } from "./release-candidate-manifest.mjs";
import { snapshotReleaseTarballs } from "./snapshot-release-tarballs.mjs";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const parseArgs = () => {
  const options = {
    artifactsDir: artifactDirectory,
    actorJourney: false,
    vcConsumer: false,
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--artifacts-dir":
        options.artifactsDir = args[++index];
        break;
      case "--manifest":
        options.manifest = args[++index];
        break;
      case "--actor-journey":
        options.actorJourney = true;
        break;
      case "--vc-consumer":
        options.vcConsumer = true;
        break;
      case "--help":
        console.log(
          [
            "Usage: node scripts/smoke-packed-artifacts.mjs [options]",
            "",
            "Options:",
            `  --artifacts-dir <dir>  Tarball directory. Defaults to ${artifactDirectory}.`,
            "  --manifest <path>     Verify the candidate manifest before installing any tarball.",
            "  --actor-journey       Run four signed HTTP journeys and the recognition VC/VP scenario from packed packages.",
            "  --vc-consumer         Compile the packed Ledger 8 consumer fixture and check its pinned authority domain.",
          ].join("\n"),
        );
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
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

const ensureArtifacts = (artifactsPath) => {
  const tarballs = fs
    .readdirSync(artifactsPath, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".tgz"));
  if (tarballs.length === artifactWorkspaces.length) {
    return;
  }

  run("node", ["scripts/pack-artifacts.mjs", "--output-dir", artifactsPath], {
    cwd: repoRoot,
  });
};

const { artifactsDir, manifest, actorJourney, vcConsumer } = parseArgs();
const resolvedArtifactsDir = path.resolve(repoRoot, artifactsDir);
let tarballPaths;
let candidateManifest;
if (manifest !== undefined) {
  if (typeof manifest !== "string" || manifest.length === 0) {
    throw new Error("--manifest requires a file path");
  }
  candidateManifest = JSON.parse(fs.readFileSync(path.resolve(repoRoot, manifest), "utf8"));
  tarballPaths = verifyReleaseCandidateArtifacts(candidateManifest, resolvedArtifactsDir);
} else {
  fs.mkdirSync(resolvedArtifactsDir, { recursive: true });
  ensureArtifacts(resolvedArtifactsDir);
  tarballPaths = fs.readdirSync(resolvedArtifactsDir)
    .filter((fileName) => fileName.endsWith(".tgz"))
    .sort()
    .map((fileName) => path.join(resolvedArtifactsDir, fileName));
}

if (tarballPaths.length !== artifactWorkspaces.length) {
  throw new Error(
    `Expected ${artifactWorkspaces.length} tarballs in ${resolvedArtifactsDir}, found ${tarballPaths.length}`,
  );
}

const smokeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "trust-registry-pack-smoke-"));

try {
  if (candidateManifest !== undefined) {
    tarballPaths = snapshotReleaseTarballs(candidateManifest, resolvedArtifactsDir,
      path.join(smokeRoot, "verified-packages"));
  }
  fs.writeFileSync(
    path.join(smokeRoot, "package.json"),
    `${JSON.stringify({ name: "trust-registry-pack-smoke", private: true, type: "module" }, null, 2)}\n`,
  );
  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballPaths], {
    cwd: smokeRoot,
  });

  const smokeImports = artifactWorkspaces.flatMap((workspace) =>
    packageManifestCatalog.get(workspace)?.smokeImports ?? [],
  );

  fs.writeFileSync(
    path.join(smokeRoot, "smoke.mjs"),
    [
      `const imports = ${JSON.stringify(smokeImports, null, 2)};`,
      "for (const specifier of imports) {",
      "  await import(specifier);",
      "  console.log(`[smoke-packed-artifacts] imported ${specifier}`);",
      "}",
      'const contract = await import("@midnight-ntwrk/trust-registry-contract");',
      'const fixtures = await import("@midnight-ntwrk/trust-registry-contract/testing");',
      'if ("labelToBytes32" in contract || typeof fixtures.labelToBytes32 !== "function") {',
      '  throw new Error("Trust Registry contract fixture exports crossed the package boundary");',
      '}',
      'const client = await import("@midnight-ntwrk/trust-registry-client");',
      'const simulator = await import("@midnight-ntwrk/trust-registry-client/simulator");',
      'if ("TrustRegistrySimulatorClient" in client || typeof simulator.TrustRegistrySimulatorClient !== "function") {',
      '  throw new Error("Trust Registry client simulator exports crossed the package boundary");',
      '}',
    ].join("\n"),
  );

  run("node", ["smoke.mjs"], { cwd: smokeRoot });
  fs.copyFileSync(
    path.join(repoRoot, "scripts/packed-consumer-scenario.mjs"),
    path.join(smokeRoot, "packed-consumer-scenario.mjs"),
  );
  run("node", ["packed-consumer-scenario.mjs"], { cwd: smokeRoot });
  if (vcConsumer) {
    fs.copyFileSync(
      path.join(repoRoot, "scripts/packed-vc-consumer-scenario.mjs"),
      path.join(smokeRoot, "packed-vc-consumer-scenario.mjs"),
    );
    const compactVersion = fs.readFileSync(path.join(repoRoot, ".compact-version"), "utf8").trim();
    run("node", ["packed-vc-consumer-scenario.mjs", compactVersion], { cwd: smokeRoot });
    console.log("[smoke-packed-artifacts] Packed Ledger 8 consumer fixture passed.");
  }
  if (actorJourney) {
    for (const script of [
      "demo-signed-membership-journey.mjs",
      "packed-recognition-journey.mjs",
      "workspace-lock-fixture.mjs",
      "hold-workspace-lock.mjs",
      "probe-workspace-restart.mjs",
    ]) {
      fs.copyFileSync(path.join(repoRoot, "scripts", script), path.join(smokeRoot, script));
    }
    for (const role of ["issuer", "verifier", "auditor", "maintainer"]) {
      run("node", ["demo-signed-membership-journey.mjs", role], { cwd: smokeRoot });
      console.log(`[smoke-packed-artifacts] Packed ${role} actor journey passed.`);
    }
    const recognitionReport = JSON.parse(run("node", ["packed-recognition-journey.mjs"], { cwd: smokeRoot }));
    if (recognitionReport.demo !== "packed-recognition-journey"
      || recognitionReport.proposalSignatureVerified !== true
      || recognitionReport.proposalApiEvidenceVerified !== true
      || !/^0x[0-9a-f]{64}$/u.test(recognitionReport.evidenceCommitment)
      || !Array.isArray(recognitionReport.signerKeyIds)
      || recognitionReport.signerKeyIds.length < 2
      || !Array.isArray(recognitionReport.expectedRejections)
      || !recognitionReport.expectedRejections.includes("missing-proposal-evidence:404")
      || !recognitionReport.expectedRejections.includes("unavailable-ledger-reader:503")
      || "vp" in recognitionReport || "assertion" in recognitionReport) {
      throw new Error("Packed recognition journey did not return a scrubbed, verified evidence report");
    }
    console.log("[smoke-packed-artifacts] Packed recognition journey passed.");
  }
  run(path.join(smokeRoot, "node_modules/.bin/trust-registry"), ["--help"], {
    cwd: smokeRoot,
  });
} finally {
  fs.rmSync(smokeRoot, { force: true, recursive: true });
}

console.log("[smoke-packed-artifacts] Local artifact tarballs install and verify a consumer scenario.");
