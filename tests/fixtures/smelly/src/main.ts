import { settleUserInvoices } from "./user/profile";
import { Transport, connect, reconnect, healthcheck } from "./net/transport";

export function main(): void {
  settleUserInvoices("u1");
  new Transport();
  connect("localhost", 8080, 30);
  reconnect("localhost", 8080, 30, 3);
  healthcheck(30, "localhost", 8080);
}

main();
