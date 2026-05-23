import { cp, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(scriptDir, "..");
const distDir = resolve(packageDir, "dist");
const publicDir = resolve(packageDir, "public");

await mkdir(distDir, { recursive: true });
await cp(publicDir, distDir, { recursive: true });
