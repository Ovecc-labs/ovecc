import { handleCreateInvoice } from "../billing/api";
import { getUser } from "../user/service";

export function checkout(userId: string): string {
  getUser(userId);
  return handleCreateInvoice(userId);
}
