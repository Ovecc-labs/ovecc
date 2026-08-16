import { createHttpServer, listDeadLetters } from "./http.js";

// The caller consumes the values without importing a single type name — which
// is exactly why reachability cannot see those types being used.
export function start() {
  const app = createHttpServer({ port: 8080 });
  listDeadLetters();
  return app;
}
