// Four worker spawns. Only the three literal ones can be resolved statically;
// the computed one is unknowable and must not be guessed at.
const signer = new Worker(new URL("./signature-worker.ts", import.meta.url));
const hasher = new Worker("./plain-worker.js");
const chosen = new Worker(new URL(process.env.WORKER_PATH, import.meta.url));

// The pool shape: bind the entry URL once, construct N workers from it. This
// is what a real worker pool looks like, so resolving only the inline form
// would miss the common case.
const poolUrl = new URL("./pool-worker.ts", import.meta.url);

export function startPool(size: number): Worker[] {
  const pool: Worker[] = [];
  for (let i = 0; i < size; i += 1) {
    pool.push(new Worker(poolUrl));
  }
  return pool;
}

export function start(): void {
  signer.postMessage("sign");
  hasher.postMessage("hash");
  chosen.postMessage("go");
}
