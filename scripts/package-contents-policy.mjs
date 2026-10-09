export const unexpectedLightContractArtifacts = (paths, managedDirectory) => {
  const managedPrefix = `dist/managed/${managedDirectory}/`;
  const lightContractPrefix = `${managedPrefix}contract/`;
  return paths.filter((path) => path.startsWith(managedPrefix) && !path.startsWith(lightContractPrefix));
};

export const missingFullContractArtifacts = (paths, managedDirectory) => {
  const managedPrefix = `dist/managed/${managedDirectory}/`;
  const circuitNames = (prefix, extension) => new Set(paths.flatMap((path) => {
    if (!path.startsWith(prefix)) return [];
    const name = path.slice(prefix.length);
    return name.length > extension.length && name.endsWith(extension) && !name.includes("/")
      ? [name.slice(0, -extension.length)]
      : [];
  }));
  const zkir = circuitNames(`${managedPrefix}zkir/`, ".zkir");
  const prover = circuitNames(`${managedPrefix}keys/`, ".prover");
  const verifier = circuitNames(`${managedPrefix}keys/`, ".verifier");
  const missing = [];
  if (zkir.size === 0) missing.push("ZK IR");
  if (prover.size === 0) missing.push("proving keys");
  if (verifier.size === 0) missing.push("verification keys");
  for (const name of [...new Set([...zkir, ...prover, ...verifier])].sort()) {
    if (!zkir.has(name)) missing.push(`ZK IR for ${name}`);
    if (!prover.has(name)) missing.push(`proving key for ${name}`);
    if (!verifier.has(name)) missing.push(`verification key for ${name}`);
  }
  return missing;
};
