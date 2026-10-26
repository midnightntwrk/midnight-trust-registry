import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertApprovedProviderTree,
  registerApprovedProviderImportBoundary,
} from "./immutable-provider-tree.mjs";

const root = process.env.TR_IMMUTABLE_PROVIDER_ROOT;
const entry = process.argv[1];
if (typeof entry !== "string") {
  throw new Error("Approved provider preloader requires a file-based CLI entry point");
}
assertApprovedProviderTree(fileURLToPath(import.meta.url), root);
assertApprovedProviderTree(resolve(entry), root);
registerApprovedProviderImportBoundary(root);
