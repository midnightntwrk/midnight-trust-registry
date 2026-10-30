/** @type {Record<"api" | "admin" | "applicant", string>} */
const targets = {
  api: "http://127.0.0.1:4400/health",
  admin: "http://127.0.0.1:4173/",
  applicant: "http://127.0.0.1:4173/",
};

/** @param {string} role */
export function approvedRuntimeHealthcheck(role) {
  if (!Object.hasOwn(targets, role)) throw new Error("Unknown runtime healthcheck role");
  const target = targets[/** @type {keyof typeof targets} */ (role)];
  return {
    Test: ["CMD-SHELL", `node -e "fetch('${target}',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`],
    Interval: 30_000_000_000,
    Timeout: 5_000_000_000,
    StartPeriod: 30_000_000_000,
    Retries: 3,
  };
}

/** @param {unknown} value @param {string} role */
export function matchesApprovedRuntimeHealthcheck(value, role) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const fields = /** @type {Record<string, unknown>} */ (value);
  const expected = approvedRuntimeHealthcheck(role);
  return Object.keys(fields).sort().join("\0") === Object.keys(expected).sort().join("\0")
    && Object.entries(expected).every(([key, approved]) =>
      Array.isArray(approved) ? JSON.stringify(fields[key]) === JSON.stringify(approved)
        : fields[key] === approved);
}
