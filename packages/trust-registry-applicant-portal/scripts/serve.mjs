import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { serveStaticAssets } from "../../../scripts/serve-static.mjs";

serveStaticAssets({
  distDir: resolve(fileURLToPath(new URL("../dist", import.meta.url))),
  defaultPort: 4175,
  name: "trust-registry-applicant-portal",
});
