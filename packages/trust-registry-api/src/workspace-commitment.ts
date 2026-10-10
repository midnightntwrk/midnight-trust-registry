import {
  TrustRegistryOperatorWorkspaceSchema,
  type TrustRegistryOperatorWorkspace,
} from "@midnight-ntwrk/trust-registry-cli";
import { canonicalizeJson, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

export function computeOperatorWorkspaceCommitment(workspace: TrustRegistryOperatorWorkspace): string {
  // Match persisted JSON semantics while normalizing key order and whitespace.
  const validated = TrustRegistryOperatorWorkspaceSchema.parse(workspace);
  const serialized = JSON.parse(JSON.stringify(validated)) as TrustRegistryOperatorWorkspace;
  return sha256Hex(JSON.stringify([
    "tr:workspace:revision:v1",
    canonicalizeJson(serialized),
  ]));
}
