export const unexpectedLightContractArtifacts = (paths, managedDirectory) => {
  const managedPrefix = `dist/managed/${managedDirectory}/`;
  const lightContractPrefix = `${managedPrefix}contract/`;
  return paths.filter((path) => path.startsWith(managedPrefix) && !path.startsWith(lightContractPrefix));
};

export const proofCircuitNames = (contractInfo) => {
  if (!Array.isArray(contractInfo?.circuits)) {
    throw new Error("Compact contract info is missing its circuits array");
  }
  const names = contractInfo.circuits.filter((circuit) => circuit?.proof === true).map((circuit) => circuit.name);
  if (names.length === 0 || names.some((name) => typeof name !== "string" || !name || name.includes("/")) ||
      new Set(names).size !== names.length) {
    throw new Error("Compact contract info has no valid, unique proof-circuit names");
  }
  return names;
};

export const missingFullContractArtifacts = (paths, managedDirectory, expectedCircuitNames) => {
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
  const expected = new Set(expectedCircuitNames);
  for (const name of [...expected].sort()) {
    if (!zkir.has(name)) missing.push(`ZK IR for ${name}`);
    if (!prover.has(name)) missing.push(`proving key for ${name}`);
    if (!verifier.has(name)) missing.push(`verification key for ${name}`);
  }
  for (const name of [...new Set([...zkir, ...prover, ...verifier])].sort()) {
    if (!expected.has(name)) missing.push(`unexpected proof artifacts for ${name}`);
  }
  return missing;
};
