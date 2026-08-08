import type { QShape } from "../q/x";

export interface PShape {
  id: string;
}

export type PairedWithQ = PShape & QShape;
