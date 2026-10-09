const managedPrefix = "dist/managed/trust-registry/";
const lightContractPrefix = `${managedPrefix}contract/`;

export const unexpectedLightContractArtifacts = (paths) => paths.filter((path) =>
  path.startsWith(managedPrefix) && !path.startsWith(lightContractPrefix));

export const missingFullContractArtifacts = (paths) => {
  const required = [
    ["proving keys", /^dist\/managed\/trust-registry\/keys\/[^/]+\.prover$/u],
    ["ZK IR", /^dist\/managed\/trust-registry\/zkir\/[^/]+\.zkir$/u],
  ];
  return required.filter(([, pattern]) => !paths.some((path) => pattern.test(path)))
    .map(([label]) => label);
};
