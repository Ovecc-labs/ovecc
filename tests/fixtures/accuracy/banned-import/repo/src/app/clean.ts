import { normalize } from "./helper";

export function tidy(id: string): string {
  return normalize(id);
}
