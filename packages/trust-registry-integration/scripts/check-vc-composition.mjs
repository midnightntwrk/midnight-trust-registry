import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(packageRoot, "../..");
const vcCompactRoot = dirname(fileURLToPath(import.meta.resolve(
  "@midnight-ntwrk/credential-compact/credentials/composable.compact",
)));
const generatedRoot = resolve(packageRoot, "src/managed");
await mkdir(generatedRoot, { recursive: true });
const output = await mkdtemp(join(generatedRoot, "vc-composition-"));

try {
  const compile = spawnSync(process.execPath, [
    resolve(repoRoot, "scripts/compile-compact.mjs"),
    "--skip-zk",
    "--compact-path", vcCompactRoot,
    resolve(packageRoot, "src/compact/vc-composition.compact"),
    output,
  ], { stdio: "inherit" });
  if (compile.error) throw compile.error;
  if (compile.status !== 0) throw new Error(`VC composition compilation failed (${compile.status})`);

  const { pureCircuits } = await import(pathToFileURL(join(output, "contract/index.js")).href);
  const bytes = (value) => new Uint8Array(32).fill(value);
  const issuer = {
    controllerAddress: { bytes: bytes(1) },
    methodId: bytes(2),
  };
  const holderBinding = {
    holderVerificationMethodRef: {
      controllerAddress: { bytes: bytes(3) },
      methodId: bytes(4),
    },
  };
  const schema = {
    packageId: bytes(5),
    schemaId: bytes(6),
    majorVersion: 1n,
    minorVersion: 0n,
  };
  const credential = {
    version: 1n,
    schema,
    issuerVerificationMethodRef: issuer,
    holderBinding,
    statusBinding: {},
    issuedAt: 1n,
    hasExpiration: false,
    expiresAt: 0n,
    claims: {},
    claimCommitments: {},
    claimRoot: bytes(7),
  };
  const presentation = {
    version: 1n,
    schema,
    credentialClaimRoot: credential.claimRoot,
    issuerVerificationMethodRef: issuer,
    holderBinding,
    disclosed: {},
  };

  assert.equal(pureCircuits.credentialBodyRoot(credential).length, 32);
  assert.equal(pureCircuits.presentationBodyRoot(presentation).length, 32);
  assert.deepEqual(pureCircuits.assertCredentialPresentationLink(credential, presentation), []);
  assert.throws(() => pureCircuits.assertCredentialPresentationLink(credential, {
    ...presentation,
    credentialClaimRoot: bytes(8),
  }), /claim root/i);
  assert.throws(() => pureCircuits.assertCredentialPresentationLink(credential, {
    ...presentation,
    issuerVerificationMethodRef: { ...issuer, methodId: bytes(9) },
  }), /issuer method/i);
  console.log("Published VC Compact composition and linkage checks passed");
} finally {
  await rm(output, { recursive: true, force: true });
}
