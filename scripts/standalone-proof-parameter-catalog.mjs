export const STANDALONE_PROOF_PARAMETER_PATHS = Object.freeze([
  ...[10, 11, 12, 13, 14, 15].map((k) => `bls_midnight_2p${k}`),
  ...["spend.prover", "spend.verifier", "spend.bzkir"].map((name) => `dust/9/${name}`),
  ...["spend", "output", "sign"].flatMap((circuit) =>
    ["prover", "verifier", "bzkir"].map((extension) => `zswap/9/${circuit}.${extension}`)),
].sort());

export const PROTOCOL_KEY_PATHS = Object.freeze(STANDALONE_PROOF_PARAMETER_PATHS
  .filter((path) => /\.(?:prover|verifier)$/u.test(path)));

export const KEYLESS_KEYGEN_PARAMETER_PATHS = Object.freeze([
  ...STANDALONE_PROOF_PARAMETER_PATHS.filter((path) => !PROTOCOL_KEY_PATHS.includes(path)),
  ...[6, 7, 9, 16, 17, 18, 19].map((k) => `bls_midnight_2p${k}`),
].sort());
