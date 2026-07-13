import { connect, reconnect, healthcheck, ping, trace } from "./net/api";

export function main(): void {
  connect("localhost", 8080, 30);
  reconnect("localhost", 8080, 30, 3);
  healthcheck(30, "localhost", 8080);
  ping("localhost", 8080);
  trace("localhost", 8080);
}

main();
