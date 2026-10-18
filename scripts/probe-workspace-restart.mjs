import assert from "node:assert/strict";

import {
  createTrustRegistryApiServer,
  createWorkspaceFileSource,
} from "@midnight-ntwrk/trust-registry-api";

const [workspacePath, expectedEpochId, role, subjectDid, resourceId, activeAt, revokedAt] = process.argv.slice(2);
if (!workspacePath || !expectedEpochId || !role) throw new Error("Expected workspace, epoch, and role");

const server = createTrustRegistryApiServer({ source: createWorkspaceFileSource(workspacePath) });
try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const base = `http://127.0.0.1:${address.port}`;
  const current = await fetch(`${base}/v1/epochs/current`);
  assert.equal(current.status, 200);
  assert.equal((await current.json()).epochId, expectedEpochId);

  if (role !== "maintainer") {
    const evaluate = async (at) => {
      const response = await fetch(`${base}/v1/authorizations/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ role, subjectDid, resourceId, at }),
      });
      const body = await response.json();
      assert.equal(response.status, 200, JSON.stringify(body));
      return body;
    };
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
    assert.equal((await evaluate(revokedAt)).trustedAtTime, false);
  }
  process.stdout.write(JSON.stringify({ restartedEpochId: expectedEpochId, historicalDecisionRecovered: role !== "maintainer" }));
} finally {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
