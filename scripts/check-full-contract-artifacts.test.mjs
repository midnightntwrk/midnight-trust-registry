import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { checkFullContractArtifacts } from "./check-full-contract-artifacts.mjs";

test("full artifact gate rejects light output, missing keys, and empty keys", () => {
  const root = mkdtempSync(path.join(tmpdir(), "tr-full-artifacts-"));
  const base = path.join(root, "contracts/trust-registry/dist");
  const source = path.join(root, "contracts/trust-registry/src/trust-registry.compact");
  const write = (relative, value) => {
    const target = path.join(base, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, value);
  };
  try {
    mkdirSync(path.dirname(source), { recursive: true });
    writeFileSync(source, "contract");
    write("trust-registry.compact", "contract");
    write("managed/trust-registry/contract/index.js", "export {};");
    assert.throws(() => checkFullContractArtifacts(root), /contract-info.json/);
    write("managed/trust-registry/compiler/contract-info.json", JSON.stringify({ circuits: [
      { name: "proposeIssuerAuthorization", proof: true },
    ] }));
    write("managed/trust-registry/zkir/proposeIssuerAuthorization.zkir", "zkir");
    write("managed/trust-registry/keys/proposeIssuerAuthorization.prover", "prover");
    assert.throws(() => checkFullContractArtifacts(root), /verification key/);
    write("managed/trust-registry/keys/proposeIssuerAuthorization.verifier", "verifier");
    assert.equal(checkFullContractArtifacts(root), 1);
    writeFileSync(source, "new contract");
    assert.throws(() => checkFullContractArtifacts(root), /Compact source differs/u);
    writeFileSync(source, "contract");
    assert.equal(checkFullContractArtifacts(root), 1);
    write("managed/trust-registry/keys/proposeIssuerAuthorization.verifier", "");
    assert.throws(() => checkFullContractArtifacts(root), /empty/);
    unlinkSync(path.join(base, "managed/trust-registry/compiler/contract-info.json"));
    assert.throws(() => checkFullContractArtifacts(root), /contract-info.json/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
