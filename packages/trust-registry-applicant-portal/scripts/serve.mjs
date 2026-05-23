import { createReadStream } from "node:fs";
import { access } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = resolve(fileURLToPath(new URL(".", import.meta.url)));
const packageDir = resolve(scriptDir, "..");
const distDir = resolve(packageDir, "dist");

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const value = process.argv[index];
  if (value?.startsWith("--")) {
    args.set(value.slice(2), process.argv[index + 1] ?? "");
    index += 1;
  }
}

const host = args.get("host") || "127.0.0.1";
const port = Number.parseInt(args.get("port") || process.env.PORT || "4175", 10);

const contentTypeForPath = (path) => {
  switch (extname(path)) {
    case ".css":
      return "text/css; charset=utf-8";
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    default:
      return "text/plain; charset=utf-8";
  }
};

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", `http://${host}:${port.toString()}`);
  const requestedPath = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const filePath = normalize(join(distDir, requestedPath));

  if (!filePath.startsWith(distDir)) {
    response.statusCode = 403;
    response.end("forbidden\n");
    return;
  }

  try {
    await access(filePath);
  } catch {
    response.statusCode = 404;
    response.end("not found\n");
    return;
  }

  response.statusCode = 200;
  response.setHeader("content-type", contentTypeForPath(filePath));
  createReadStream(filePath).pipe(response);
});

server.listen(port, host, () => {
  process.stdout.write(`trust-registry-applicant-portal listening on http://${host}:${port.toString()}\n`);
});
