import { createConnection, createServer } from "node:net";
import { fileURLToPath } from "node:url";

const ROUTES = Object.freeze([
  { listenPort: 30944, host: "node", targetPort: 9944 },
  { listenPort: 38088, host: "indexer", targetPort: 8088 },
  { listenPort: 36300, host: "proof-server", targetPort: 6300 },
]);

export async function startInstallRelay(routes = ROUTES, bindHost = "0.0.0.0") {
  const servers = [];
  try {
    for (const route of routes) {
      const server = createServer({ allowHalfOpen: true }, (client) => {
        const upstream = createConnection({ host: route.host, port: route.targetPort,
          allowHalfOpen: true });
        client.on("error", () => upstream.destroy());
        upstream.on("error", () => client.destroy());
        client.on("close", () => upstream.destroy());
        upstream.on("close", () => client.destroy());
        client.pipe(upstream);
        upstream.pipe(client);
      });
      await new Promise((resolve, reject) => {
        const onError = (error) => reject(error);
        server.once("error", onError);
        server.listen(route.listenPort, bindHost, () => {
          server.off("error", onError);
          resolve();
        });
      });
      servers.push(server);
    }
    return servers;
  } catch (error) {
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startInstallRelay().catch((error) => {
    console.error(`Installation relay failed: ${error.message}`);
    process.exitCode = 1;
  });
}
