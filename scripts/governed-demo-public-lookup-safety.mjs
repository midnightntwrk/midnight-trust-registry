import {
  createIssuerScenarioFixture,
  createVerifierScenarioFixture,
} from "../packages/trust-registry-integration/dist/index.js";

export async function runPublicLookupSafety(matrix, { base, issuer, verifier, recognition, expectHttp }) {
  await expectHttp(await fetch(
    `${base}/v1/governed/issuer/${recognition.recognitionId}/actions/approve`,
  ), 404);
  await matrix.expectHttp(await fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      role: "issuer", subjectDid: issuer.subjectDid,
      resourceId: createIssuerScenarioFixture("wrong-scope").resourceId,
    }),
  }), {
    id: "issuer-wrong-resource-api",
    invariant: "The public lookup cannot substitute another issuer credential-family scope",
    boundary: "api",
    status: 404,
    problemType: "authorization-not-found",
  });
  await matrix.expectHttp(await fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      role: "verifier", subjectDid: verifier.subjectDid,
      resourceId: createVerifierScenarioFixture("wrong-scope").scopeResourceId,
    }),
  }), {
    id: "verifier-wrong-resource-api",
    invariant: "The public lookup cannot substitute another verifier request-profile scope",
    boundary: "api",
    status: 404,
    problemType: "authorization-not-found",
  });
  await matrix.expectHttp(await fetch(`${base}/v1/recognitions/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      recognizedAuthorityDid: recognition.recognizedAuthorityDid,
      recognizedRegistryId: "registry:external:wrong:v1",
      scopeResourceType: recognition.scopeResourceType,
      scopeResourceId: recognition.scopeResourceId,
    }),
  }), {
    id: "recognition-wrong-external-registry-api",
    invariant: "The public lookup cannot substitute a different recognized external registry",
    boundary: "api",
    status: 404,
    problemType: "recognition-not-found",
  });
}
