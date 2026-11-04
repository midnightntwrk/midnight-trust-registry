import { cp, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(scriptDir, "..");
const distDir = resolve(packageDir, "dist");
const publicDir = resolve(packageDir, "public");

await mkdir(distDir, { recursive: true });
await cp(publicDir, distDir, { recursive: true });
await cp(resolve(packageDir, "../trust-registry-ui/brand.css"), resolve(distDir, "brand.css"));
await cp(resolve(packageDir, "../trust-registry-ui/midnight-logo.svg"), resolve(distDir, "midnight-logo.svg"));
await mkdir(resolve(distDir, "fonts"), { recursive: true });
await cp(resolve(packageDir, "../trust-registry-ui/fonts/outfit-latin.woff2"), resolve(distDir, "fonts/outfit-latin.woff2"));
