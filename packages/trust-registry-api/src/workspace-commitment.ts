import {
  TrustRegistryOperatorWorkspaceSchema,
  type TrustRegistryOperatorWorkspace,
} from "@midnight-ntwrk/trust-registry-cli";
import { canonicalizeJson, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

export function computeOperatorWorkspaceCommitment(workspace: TrustRegistryOperatorWorkspace): string {
  const validated = TrustRegistryOperatorWorkspaceSchema.parse(workspace);
  return sha256Hex(JSON.stringify([
    "tr:workspace:revision:v1",
    canonicalizeJson(validated),
  ]));
}
