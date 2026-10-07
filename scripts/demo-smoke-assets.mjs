import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const importSpecifiers = (file, source) => {
  const specifiers = [];
  const syntax = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      specifiers.push(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword && node.arguments[0] && ts.isStringLiteral(node.arguments[0])) {
      specifiers.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };
  visit(syntax);
  return specifiers.filter((specifier) => specifier.startsWith("."));
};

export function assertUiIndexResponse(response, title) {
  if (!response.ok) throw new Error(`${title} served index.html with HTTP ${response.status}`);
}

export function collectEmittedModuleAssets(distDir, title) {
  const root = path.resolve(distDir);
  const modules = [];
  const assets = new Set();
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(fullPath);
      else if (entry.isFile() && entry.name.endsWith(".js")) modules.push(fullPath);
    }
  };
  walk(root);
  const indexPath = path.join(root, "index.js");
  if (!modules.includes(indexPath)) throw new Error(`${title} build is missing index.js`);

  const importsByModule = new Map();
  for (const modulePath of modules) {
    const source = fs.readFileSync(modulePath, "utf8");
    const imports = [];
    for (const specifier of importSpecifiers(modulePath, source)) {
      const imported = path.resolve(path.dirname(modulePath), specifier);
      const relative = path.relative(root, imported);
      if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        throw new Error(`${title} ${path.relative(root, modulePath)} imports outside dist: ${specifier}`);
      }
      if (![".js", ".json"].includes(path.extname(imported)) || !fs.existsSync(imported) || !fs.statSync(imported).isFile()) {
        throw new Error(`${title} ${path.relative(root, modulePath)} imports missing module asset: ${specifier}`);
      }
      imports.push(imported);
      assets.add(relative.split(path.sep).join("/"));
    }
    importsByModule.set(modulePath, imports);
  }
  const visited = new Set();
  const visit = (modulePath) => {
    if (visited.has(modulePath)) return;
    visited.add(modulePath);
    if (fs.statSync(modulePath).size === 0) {
      throw new Error(`${title} reachable module is empty: ${path.relative(root, modulePath)}`);
    }
    for (const imported of importsByModule.get(modulePath) ?? []) {
      if (imported.endsWith(".js")) visit(imported);
    }
  };
  visit(indexPath);
  return [...new Set([...modules.map((modulePath) => path.relative(root, modulePath).split(path.sep).join("/")), ...assets])].sort();
}
