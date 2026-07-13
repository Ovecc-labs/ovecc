import {
  reserveItem,
  releaseItem,
  countItems,
  restock,
  auditStock,
  syncStock,
} from "../inventory/stock";

export function finalizeOrder(orderId: string): number {
  const item = reserveItem(orderId);
  releaseItem(item);
  const count = countItems(item);
  auditStock(item);
  syncStock(item);
  restock(item);
  return count;
}

export function tidyOrder(orderId: string): number {
  const item = reserveItem(orderId);
  return countItems(item);
}
