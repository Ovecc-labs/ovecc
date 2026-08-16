import { spawn } from "node:child_process";

// The task is named as a string and run by a child process. No import edge
// exists, so reachability cannot see it — but the literal can.
export function build(): void {
  spawn("node", ["tasks/build.ts"], { stdio: "inherit" });
}
