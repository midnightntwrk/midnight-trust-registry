const managedPrefix = "dist/managed/trust-registry/";
const lightContractPrefix = `${managedPrefix}contract/`;

export const unexpectedLightContractArtifacts = (paths) => paths.filter((path) =>
  path.startsWith(managedPrefix) && !path.startsWith(lightContractPrefix));
