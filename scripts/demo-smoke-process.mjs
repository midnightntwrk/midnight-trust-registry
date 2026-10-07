export function describeChildExit(child) {
  return child.signalCode === null
    ? `code ${child.exitCode ?? "unknown"}`
    : `signal ${child.signalCode}`;
}

export async function stopChild(child, { graceMs = 2000, hardMs = 4000 } = {}) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { forced: false, timedOut: false };
  }
  return await new Promise((resolve) => {
    let forced = false;
    let settled = false;
    let graceTimer;
    let hardTimer;
    const finish = (timedOut) => {
      if (settled) return;
      settled = true;
      clearTimeout(graceTimer);
      clearTimeout(hardTimer);
      child.off("exit", onExit);
      resolve({ forced, timedOut });
    };
    const onExit = () => finish(false);
    child.once("exit", onExit);
    graceTimer = setTimeout(() => {
      forced = true;
      child.kill("SIGKILL");
    }, graceMs);
    hardTimer = setTimeout(() => {
      child.stdout?.destroy();
      child.stderr?.destroy();
      child.unref();
      finish(true);
    }, hardMs);
    if (child.exitCode !== null || child.signalCode !== null) {
      finish(false);
      return;
    }
    child.kill("SIGTERM");
  });
}
