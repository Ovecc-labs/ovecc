import {
  openLedger,
  postEntry,
  balance,
  closeLedger,
  auditTrail,
  reconcile,
} from "../billing/ledger";

export function settleUserInvoices(userId: string): number {
  const ledger = openLedger(userId);
  postEntry(ledger);
  postEntry(userId);
  const due = balance(ledger);
  auditTrail(ledger);
  reconcile(ledger);
  closeLedger(ledger);
  return due;
}
