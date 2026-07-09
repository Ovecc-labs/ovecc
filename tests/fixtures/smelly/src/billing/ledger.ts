export function openLedger(id: string): string {
  return id;
}

export function postEntry(entry: string): string {
  return entry;
}

export function balance(id: string): number {
  return id.length;
}

export function closeLedger(id: string): string {
  return id;
}

export function auditTrail(id: string): string[] {
  return [id];
}

export function reconcile(id: string): boolean {
  return id.length > 0;
}
