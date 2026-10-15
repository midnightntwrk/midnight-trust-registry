import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import yaml from "js-yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const document = yaml.load(readFileSync(resolve(root, "docs-site/public/openapi.yaml"), "utf8"));

if (document.openapi !== "3.1.0" || !document.info?.version || !document.paths) {
  throw new Error("OpenAPI document is missing its version, info, or paths");
}

if (document.security?.length !== 1 || Object.keys(document.security[0] ?? {}).length !== 0) {
  throw new Error("OpenAPI must declare anonymous HTTP access; mutations are signed in their bodies");
}

const signers = document.components?.schemas?.GovernedSigners?.properties?.signers;
if (signers?.minItems !== 1 || signers.maxItems !== 16) {
  throw new Error("OpenAPI signer bounds must match GovernedMembershipSignersSchema");
}

const requiredPaths = [
  "/health",
  "/v1/registry",
  "/v1/epochs/current",
  "/v1/authorizations/{role}/{id}/evidence",
  "/v1/authorizations/evaluate",
  "/v1/recognitions/evaluate",
  "/v1/pending-applications",
  "/v1/application-evidence/{id}/submissions",
  "/v1/governed/{role}/{id}/proposal/submit",
  "/v1/governed/{role}/{id}/actions/{action}",
  "/v1/governed/epochs/publish",
  "/v1/trqp/authorizations/query",
];

for (const path of requiredPaths) {
  if (!document.paths[path]) throw new Error(`Missing OpenAPI path: ${path}`);
}

const actionSource = readFileSync(resolve(root, "packages/trust-registry-api/src/governed-membership-actions.ts"), "utf8");
const actionDeclaration = /GovernedMembershipActionSchema\s*=\s*z\.enum\((\[[^\]]+\])\)/u.exec(actionSource);
if (actionDeclaration === null) throw new Error("Cannot read the governed membership action schema");
const supportedActions = JSON.parse(actionDeclaration[1]);
const governedActionPath = document.paths["/v1/governed/{role}/{id}/actions/{action}"];
const documentedActions = governedActionPath.parameters?.find((parameter) => parameter.name === "action")?.schema?.enum;
if (JSON.stringify(documentedActions) !== JSON.stringify(supportedActions)) {
  throw new Error("OpenAPI governed lifecycle actions do not match GovernedMembershipActionSchema");
}

for (const [path, item] of Object.entries(document.paths)) {
  const parameters = new Set((item.parameters ?? []).map((parameter) => parameter.name));
  for (const name of path.matchAll(/\{([^}]+)\}/g)) {
    if (!parameters.has(name[1])) throw new Error(`Missing path parameter ${name[1]} in ${path}`);
  }
  for (const method of ["get", "post", "put", "patch", "delete"]) {
    const operation = item[method];
    if (!operation) continue;
    if (!operation.summary || !operation.responses || !Object.keys(operation.responses).some((status) => status.startsWith("2"))) {
      throw new Error(`Incomplete OpenAPI operation: ${method.toUpperCase()} ${path}`);
    }
  }
}

console.log(`OpenAPI check passed: ${Object.keys(document.paths).length} paths`);
