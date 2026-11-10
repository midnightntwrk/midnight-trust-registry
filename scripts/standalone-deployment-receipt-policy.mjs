const HASH = /^0x[0-9a-f]{64}$/u;
const ZERO_HASH = /^0x0{64}$/u;

/**
 * @param {unknown} receipt
 * @param {string} networkId
 * @returns {boolean}
 */
export function validLocalDeploymentReceipt(receipt, networkId) {
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) return false;
  const value = /** @type {Record<string, unknown>} */ (receipt);
  return value.networkId === networkId
    && typeof value.contractAddress === "string"
    && HASH.test(value.contractAddress) && !ZERO_HASH.test(value.contractAddress)
    && typeof value.blockHash === "string"
    && HASH.test(value.blockHash) && !ZERO_HASH.test(value.blockHash)
    && typeof value.txId === "string" && value.txId.length > 0
    && typeof value.blockHeight === "number"
    && Number.isSafeInteger(value.blockHeight) && value.blockHeight >= 0;
}
