import type { PShape } from "../p/x";

export interface QShape {
  total: number;
}

export type PairedWithP = QShape & PShape;
