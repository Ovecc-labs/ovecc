import { finalizeOrder, tidyOrder } from "./orders/checkout";

export function main(): void {
  finalizeOrder("o1");
  tidyOrder("o2");
}

main();
