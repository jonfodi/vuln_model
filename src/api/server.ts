import { closeDb } from "../db";
import { handleApiRequest } from "./handler";

const SEARCH_TIMEOUT_SECONDS = 30;

type StartServerOptions = {
  port?: number;
  development?: boolean;
};

export function startServer(options?: StartServerOptions) {
  const server = Bun.serve({
    ...(options?.port === undefined ? {} : { port: options.port }),
    development: options?.development ?? process.env.NODE_ENV !== "production",
    idleTimeout: SEARCH_TIMEOUT_SECONDS,
    fetch(request, server) {
      server.timeout(request, SEARCH_TIMEOUT_SECONDS);
      return handleApiRequest(request);
    },
    error(error) {
      console.error(error);
      return Response.json(
        { error: "internal_error", message: "Internal server error." },
        { status: 500 },
      );
    },
  });

  console.log(`Vulnerability intelligence API listening on ${server.url}`);
  return server;
}

if (import.meta.main) {
  const server = startServer();

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, async () => {
      await server.stop();
      await closeDb();
      process.exit(0);
    });
  }
}
