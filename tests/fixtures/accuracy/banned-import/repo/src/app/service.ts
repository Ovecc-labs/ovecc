import { loadRecord } from "../legacy/store";

export function serve(id: string): string {
  return loadRecord(id);
}
