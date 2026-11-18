import {
  TrustRegistryOperatorWorkspaceSchema,
  type TrustRegistryOperatorWorkspace,
} from "@midnightntwrk/trust-registry-cli";
import { canonicalizeJson, sha256Hex } from "@midnightntwrk/trust-registry-domain";

export function computeOperatorWorkspaceCommitment(workspace: TrustRegistryOperatorWorkspace): string {
  // Match persisted JSON semantics while normalizing key order and whitespace.
  const validated = TrustRegistryOperatorWorkspaceSchema.parse(workspace);
  const serialized = JSON.parse(JSON.stringify(validated)) as TrustRegistryOperatorWorkspace;
  return sha256Hex(JSON.stringify([
    "tr:workspace:revision:v1",
    canonicalizeJson(serialized),
  ]));
}
