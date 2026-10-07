import fs from "node:fs";
import path from "node:path";

const importSpecifiers = (source) => [
  ...source.matchAll(/\b(?:import|export)\s+(?:[^;"']*?\s+from\s+)?["'](\.[^"']+)["']/gu),
  ...source.matchAll(/\bimport\s*\(\s*["'](\.[^"']+)["']\s*\)/gu),
].map((match) => match[1]);

export function assertUiIndexResponse(response, title) {
  if (!response.ok) throw new Error(`${title} served index.html with HTTP ${response.status}`);
}

export function collectEmittedJavaScriptAssets(distDir) {
  const root = path.resolve(distDir);
  const modules = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(fullPath);
      else if (entry.isFile() && entry.name.endsWith(".js")) modules.push(fullPath);
    }
  };
  walk(root);
  const indexPath = path.join(root, "index.js");
  if (!modules.includes(indexPath)) throw new Error("build is missing index.js");

  for (const modulePath of modules) {
    const source = fs.readFileSync(modulePath, "utf8");
    for (const specifier of importSpecifiers(source)) {
      const imported = path.resolve(path.dirname(modulePath), specifier);
      const relative = path.relative(root, imported);
      if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        throw new Error(`${path.relative(root, modulePath)} imports outside dist: ${specifier}`);
      }
      if (!imported.endsWith(".js") || !fs.existsSync(imported) || !fs.statSync(imported).isFile()) {
        throw new Error(`${path.relative(root, modulePath)} imports missing JavaScript module: ${specifier}`);
      }
    }
  }
  return modules.map((modulePath) => path.relative(root, modulePath).split(path.sep).join("/")).sort();
}
