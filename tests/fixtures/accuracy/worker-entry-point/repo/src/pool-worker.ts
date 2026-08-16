// Constructed through a URL bound to a `const` — the worker-pool shape.
import { parentPort } from "node:worker_threads";

parentPort?.on("message", (message: string) => {
  parentPort?.postMessage(`pooled:${message}`);
});
