export const unexpectedLightContractArtifacts = (paths, managedDirectory) => {
  const managedPrefix = `dist/managed/${managedDirectory}/`;
  const lightContractPrefix = `${managedPrefix}contract/`;
  return paths.filter((path) => path.startsWith(managedPrefix) && !path.startsWith(lightContractPrefix));
};

export const missingFullContractArtifacts = (paths, managedDirectory) => {
  const managedPrefix = `dist/managed/${managedDirectory}/`;
  const required = [
    ["proving keys", `${managedPrefix}keys/`, /^[^/]+\.prover$/u],
    ["ZK IR", `${managedPrefix}zkir/`, /^[^/]+\.zkir$/u],
  ];
  return required.filter(([, prefix, pattern]) => !paths.some((path) =>
    path.startsWith(prefix) && pattern.test(path.slice(prefix.length))))
    .map(([label]) => label);
};
