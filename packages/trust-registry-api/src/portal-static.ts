import { constants } from "node:fs";
import { lstat, open, realpath, stat } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, isAbsolute, join, sep } from "node:path";

const MAX_ASSET_BYTES = 32 * 1024 * 1024;
const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

const sendError = (response: ServerResponse, status: number): void => {
  response.statusCode = status;
  response.end(status === 404 ? "not found\n" : "bad request\n");
};

/** Serve immutable portal assets from the API origin; the image builder owns their bytes. */
export async function createPortalStaticHandler(root: string): Promise<
  (request: IncomingMessage, response: ServerResponse) => Promise<void>
> {
  if (!isAbsolute(root)) throw new Error("Portal asset root must be absolute");
  const roots = Object.fromEntries(await Promise.all(["admin", "applicant"].map(async (role) => {
    if (!(await lstat(join(root, role))).isDirectory()
      || !(await lstat(join(root, role, "index.html"))).isFile()
      || !(await lstat(join(root, role, "index.js"))).isFile()) {
      throw new Error("Portal asset root requires regular packaged files");
    }
    const directory = await realpath(join(root, role));
    if (!(await stat(directory)).isDirectory()) throw new Error("Portal asset root is not a directory");
    for (const entry of ["index.html", "index.js"]) {
      const path = await realpath(join(directory, entry));
      if (!path.startsWith(`${directory}${sep}`) || !(await stat(path)).isFile()) {
        throw new Error(`Portal asset root lacks a regular ${entry}`);
      }
    }
    return [role, directory];
  }))) as Record<"admin" | "applicant", string>;

  return async (request, response) => {
    let url: URL;
    try {
      url = new URL(request.url ?? "/", "http://127.0.0.1");
    } catch {
      return sendError(response, 400);
    }
    const match = /^\/(admin|applicant)(\/.*)?$/u.exec(url.pathname);
    if (match === null) return sendError(response, 404);
    const role = match[1] as "admin" | "applicant";
    if (match[2] === undefined) {
      response.statusCode = 308;
      response.setHeader("location", `/${role}/${url.search}`);
      response.end();
      return;
    }
    let segments: string[];
    try {
      segments = (match[2].slice(1) || "index.html").split("/").map(decodeURIComponent);
    } catch {
      return sendError(response, 400);
    }
    if (segments.some((segment) => segment.length === 0 || segment === "." || segment === ".."
      || /[\\/\0]/u.test(segment))) return sendError(response, 400);
    const type = CONTENT_TYPES[extname(segments.at(-1)!)];
    if (type === undefined) return sendError(response, 404);
    const directory = roots[role];
    let file;
    let bytes: Buffer;
    try {
      const candidate = join(directory, ...segments);
      if (!(await lstat(candidate)).isFile()) return sendError(response, 404);
      const path = await realpath(candidate);
      if (!path.startsWith(`${directory}${sep}`)) return sendError(response, 404);
      file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const info = await file.stat();
      if (!info.isFile() || info.size === 0 || info.size > MAX_ASSET_BYTES) return sendError(response, 404);
      bytes = await file.readFile();
      if (bytes.length !== info.size) return sendError(response, 404);
    } catch {
      return sendError(response, 404);
    } finally {
      await file?.close();
    }
    response.statusCode = 200;
    response.setHeader("content-type", type);
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    response.end(bytes);
  };
}
