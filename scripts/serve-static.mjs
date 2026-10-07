import { createReadStream } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, sep } from "node:path";

const isInside = (path, root) => path === root || path.startsWith(`${root}${sep}`);

function rawPathname(target) {
  if (target.startsWith("/")) return target.split("?")[0];
  if (!/^https?:\/\/[^/?#]+(?:[/?#]|$)/u.test(target)) return null;
  try {
    new URL(target);
  } catch {
    return null;
  }
  const authorityEnd = target.indexOf("/", target.indexOf("://") + 3);
  return authorityEnd < 0 ? "/" : target.slice(authorityEnd).split("?")[0];
}

function contentTypeForPath(path) {
  switch (extname(path)) {
    case ".css": return "text/css; charset=utf-8";
    case ".html": return "text/html; charset=utf-8";
    case ".js": return "text/javascript; charset=utf-8";
    case ".json": return "application/json; charset=utf-8";
    default: return "text/plain; charset=utf-8";
  }
}

export function serveStaticAssets({ distDir, defaultPort, name }) {
  const args = new Map();
  for (let index = 2; index < process.argv.length; index += 1) {
    const value = process.argv[index];
    if (value?.startsWith("--")) {
      args.set(value.slice(2), process.argv[index + 1] ?? "");
      index += 1;
    }
  }
  const host = args.get("host") || "127.0.0.1";
  const port = Number.parseInt(args.get("port") || process.env.PORT || String(defaultPort), 10);
  let realDistDir;
  const resolvedDistDir = async () => {
    if (realDistDir === undefined) realDistDir = await realpath(distDir);
    return realDistDir;
  };

  const server = createServer(async (request, response) => {
    let pathname;
    try {
      const raw = rawPathname(request.url ?? "/");
      if (raw === null) throw new Error("Invalid request target");
      pathname = decodeURIComponent(raw);
    } catch {
      response.statusCode = 400;
      response.end("bad request\n");
      return;
    }
    const requestedPath = pathname === "/" ? "index.html" : pathname.slice(1);
    const filePath = normalize(join(distDir, requestedPath));
    if (!isInside(filePath, distDir)) {
      response.statusCode = 403;
      response.end("forbidden\n");
      return;
    }

    let realFilePath;
    let realRoot;
    try {
      [realFilePath, realRoot] = await Promise.all([realpath(filePath), resolvedDistDir()]);
    } catch {
      response.statusCode = 404;
      response.end("not found\n");
      return;
    }
    if (!isInside(realFilePath, realRoot)) {
      response.statusCode = 403;
      response.end("forbidden\n");
      return;
    }
    try {
      if (!(await stat(realFilePath)).isFile()) {
        response.statusCode = 404;
        response.end("not found\n");
        return;
      }
    } catch {
      response.statusCode = 404;
      response.end("not found\n");
      return;
    }

    response.statusCode = 200;
    response.setHeader("content-type", contentTypeForPath(realFilePath));
    createReadStream(realFilePath).on("error", (error) => {
      process.stderr.write(`${name} static read failed: ${error.message}\n`);
      if (response.headersSent) response.destroy(error);
      else {
        response.statusCode = 500;
        response.end("server error\n");
      }
    }).pipe(response);
  });

  server.listen(port, host, () => {
    process.stdout.write(`${name} listening on http://${host}:${port.toString()}\n`);
  });
}
