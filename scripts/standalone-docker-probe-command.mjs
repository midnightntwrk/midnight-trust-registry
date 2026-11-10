import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

/** @typedef {{ code: number, stdout: string, stderr: string }} DockerProbeResult */

/**
 * @param {string[]} args
 * @param {boolean} [allowFailure]
 * @returns {Promise<DockerProbeResult>}
 */
export async function executeDockerProbe(args, allowFailure = false) {
  try {
    const { stdout, stderr } = await run("docker", args, { timeout: 20_000, maxBuffer: 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (allowFailure && error && typeof error === "object" && "code" in error
      && typeof error.code === "number" && Number.isInteger(error.code)) {
      return { code: error.code,
        stdout: "stdout" in error && typeof error.stdout === "string" ? error.stdout : "",
        stderr: "stderr" in error && typeof error.stderr === "string" ? error.stderr : "" };
    }
    throw error;
  }
}

/**
 * @param {DockerProbeResult} result
 * @param {string} description
 */
export function requireDockerProbeSuccess(result, description) {
  if (result.code !== 0) throw new Error(`${description} failed`);
  return result.stdout.trim();
}
