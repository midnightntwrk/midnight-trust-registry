import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import yaml from "js-yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const document = yaml.load(readFileSync(resolve(root, "docs-site/public/openapi.yaml"), "utf8"));

if (document.openapi !== "3.1.0" || !document.info?.version || !document.paths) {
  throw new Error("OpenAPI document is missing its version, info, or paths");
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
