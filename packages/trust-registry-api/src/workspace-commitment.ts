import {
  TrustRegistryOperatorWorkspaceSchema,
  type TrustRegistryOperatorWorkspace,
} from "@midnight-ntwrk/trust-registry-cli";
import { canonicalizeJson, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

export function computeOperatorWorkspaceCommitment(workspace: TrustRegistryOperatorWorkspace): string {
  const validated = TrustRegistryOperatorWorkspaceSchema.parse(workspace);
  // Commit to the JSON representation actually written to the workspace file.
  const serialized = JSON.parse(JSON.stringify(validated)) as TrustRegistryOperatorWorkspace;
  return sha256Hex(JSON.stringify([
    "tr:workspace:revision:v1",
    canonicalizeJson(serialized),
  ]));
}
