import { serveStaticAssets } from "./serve-static.mjs";

if (!["admin", "applicant"].includes(process.env.TR_STATIC_ROLE)) {
  throw new Error("Static runtime role must be admin or applicant");
}

serveStaticAssets({
  distDir: "/app/public",
  defaultPort: 4173,
  name: `trust-registry-${process.env.TR_STATIC_ROLE}`,
});
