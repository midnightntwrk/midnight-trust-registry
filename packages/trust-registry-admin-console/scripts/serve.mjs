import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { serveStaticAssets } from "../../../scripts/serve-static.mjs";

serveStaticAssets({
  distDir: resolve(fileURLToPath(new URL("../dist", import.meta.url))),
  defaultPort: 4173,
  name: "trust-registry-admin-console",
});
