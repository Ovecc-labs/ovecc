import { createInvoice } from "./service";
import { getUser } from "../user/service";

export function handleCreateInvoice(userId: string): string {
  return createInvoice(getUser(userId));
}
