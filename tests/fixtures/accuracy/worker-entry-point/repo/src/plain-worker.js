// The plain-string worker form: `new Worker("./plain-worker.js")`.
import { parentPort } from "node:worker_threads";

parentPort?.on("message", (message) => {
  parentPort?.postMessage(`hashed:${message}`);
});
