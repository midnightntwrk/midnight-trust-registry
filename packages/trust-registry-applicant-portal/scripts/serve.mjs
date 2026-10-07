import { createReadStream } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = resolve(fileURLToPath(new URL(".", import.meta.url)));
const packageDir = resolve(scriptDir, "..");
const distDir = resolve(packageDir, "dist");
const realDistDir = await realpath(distDir);
const isInsideDist = (path, root) => path === root || path.startsWith(`${root}${sep}`);

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
  let pathname;
  try {
    pathname = decodeURIComponent((request.url ?? "/").split("?")[0]);
  } catch {
    response.statusCode = 400;
    response.end("bad request\n");
    return;
  }
  if (!pathname.startsWith("/")) {
    response.statusCode = 400;
    response.end("bad request\n");
    return;
  }
  const requestedPath = pathname === "/" ? "index.html" : pathname.slice(1);
  const filePath = normalize(join(distDir, requestedPath));

  if (!isInsideDist(filePath, distDir)) {
    response.statusCode = 403;
    response.end("forbidden\n");
    return;
  }

  let realFilePath;
  try {
    realFilePath = await realpath(filePath);
  } catch {
    response.statusCode = 404;
    response.end("not found\n");
    return;
  }
  if (!isInsideDist(realFilePath, realDistDir)) {
    response.statusCode = 403;
    response.end("forbidden\n");
    return;
  }
  let isFile;
  try {
    isFile = (await stat(realFilePath)).isFile();
  } catch {
    isFile = false;
  }
  if (!isFile) {
    response.statusCode = 404;
    response.end("not found\n");
    return;
  }

  response.statusCode = 200;
  response.setHeader("content-type", contentTypeForPath(realFilePath));
  createReadStream(realFilePath).on("error", () => response.destroy()).pipe(response);
});

server.listen(port, host, () => {
  process.stdout.write(`trust-registry-applicant-portal listening on http://${host}:${port.toString()}\n`);
});
