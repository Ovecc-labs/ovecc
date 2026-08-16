// Three worker spawns. Only the two literal ones can be resolved statically;
// the computed one is unknowable and must not be guessed at.
const signer = new Worker(new URL("./signature-worker.ts", import.meta.url));
const hasher = new Worker("./plain-worker.js");
const chosen = new Worker(new URL(process.env.WORKER_PATH, import.meta.url));

export function start(): void {
  signer.postMessage("sign");
  hasher.postMessage("hash");
  chosen.postMessage("go");
}
