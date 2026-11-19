import { createLocalDeploymentMaterial as createSmokeMaterial } from "./local-smoke-provider.mjs";

export { createLocalMaintenanceMaterial } from "./local-smoke-provider.mjs";

/** @param {Record<string, unknown>} bootstrap
 * @param {{registryId: string, commitment: string}} policy */
export function policyBoundSmokeBootstrap(bootstrap, policy) {
  if (typeof policy?.registryId !== "string" || policy.registryId.length === 0
    || typeof policy.commitment !== "string" || !/^0x[0-9a-f]{64}$/u.test(policy.commitment)) {
    throw new Error("Policy-bound smoke provider requires the approved canonical policy input");
  }
  return {
    ...bootstrap,
    registryId: policy.registryId,
    governancePolicyCommitment: Buffer.from(policy.commitment.slice(2), "hex"),
  };
}

/** Development-only provider for a new, policy-bound staged local deployment. */
export async function createLocalDeploymentMaterial(input, env = process.env) {
  if (!input?.approvedPolicy) {
    throw new Error("Policy-bound smoke provider requires the approved canonical policy input");
  }
  const approvedBootstrap = policyBoundSmokeBootstrap({}, input.approvedPolicy);
  const material = await createSmokeMaterial(input, env);
  return {
    ...material,
    bootstrap: { ...material.bootstrap, ...approvedBootstrap },
  };
}
