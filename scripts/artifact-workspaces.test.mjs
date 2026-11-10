#!/usr/bin/env node

import { strict as assert } from "node:assert";

import {
  artifactWorkspaces,
  localOnlyArtifactWorkspaces,
  packageManifestCatalog,
  publishWorkspaces,
  workspaceCatalog,
} from "./trust-registry-workspace-catalog.mjs";

assert.equal(
  new Set(workspaceCatalog.map(({ workspace }) => workspace)).size,
  workspaceCatalog.length,
  "workspace catalog paths must be unique",
);

assert.ok(
  publishWorkspaces.length > 0,
  "publish workspace catalog must contain at least one remotely publishable package",
);
assert.ok(
  localOnlyArtifactWorkspaces.length > 0,
  "artifact workspace catalog must track local-only packages separately",
);
assert.ok(
  publishWorkspaces.every((workspace) => artifactWorkspaces.includes(workspace)),
  "publish workspace catalog must be a subset of artifact workspaces",
);
assert.equal(
  new Set([...publishWorkspaces, ...localOnlyArtifactWorkspaces]).size,
  artifactWorkspaces.length,
  "publishable and local-only artifact workspaces must partition artifact coverage",
);

for (const workspace of artifactWorkspaces) {
  const manifest = packageManifestCatalog.get(workspace);
  assert.ok(manifest, `${workspace} must define artifact manifest expectations`);
  assert.ok(manifest.name.startsWith("@midnight-ntwrk/"));
  assert.ok(Array.isArray(manifest.files) && manifest.files.length > 0);
  assert.ok(Array.isArray(manifest.exports) && manifest.exports.length > 0);
  assert.ok(
    Array.isArray(manifest.requiredPackedPaths)
      && manifest.requiredPackedPaths.length > 0,
  );
  assert.ok(
    Array.isArray(manifest.smokeImports) && manifest.smokeImports.length > 0,
  );
}

console.log("artifact workspace catalog checks passed.");
