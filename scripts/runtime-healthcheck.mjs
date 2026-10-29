const targets = {
  api: "http://127.0.0.1:4400/health",
  admin: "http://127.0.0.1:4173/",
  applicant: "http://127.0.0.1:4173/",
};

export function approvedRuntimeHealthcheck(role) {
  const target = targets[role];
  if (target === undefined) throw new Error("Unknown runtime healthcheck role");
  return {
    Test: ["CMD-SHELL", `node -e "fetch('${target}',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`],
    Interval: 30_000_000_000,
    Timeout: 5_000_000_000,
    StartPeriod: 30_000_000_000,
    Retries: 3,
  };
}

export function matchesApprovedRuntimeHealthcheck(value, role) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const expected = approvedRuntimeHealthcheck(role);
  return Object.keys(value).sort().join("\0") === Object.keys(expected).sort().join("\0")
    && Object.entries(expected).every(([key, approved]) =>
      Array.isArray(approved) ? JSON.stringify(value[key]) === JSON.stringify(approved)
        : value[key] === approved);
}
