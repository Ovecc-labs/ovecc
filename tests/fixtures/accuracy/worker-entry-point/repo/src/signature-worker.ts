// A worker entry: the runtime loads it by URL, nothing imports it.
import { parentPort } from "node:worker_threads";

parentPort?.on("message", (message: string) => {
  parentPort?.postMessage(`signed:${message}`);
});
