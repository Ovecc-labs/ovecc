import { gone } from "./missing";
import { alsoGone } from "../nowhere/deleted.ts";
import styles from "./theme.css";
import iconUrl from "./icon.svg?url";
import { ambient } from "./ambient";
import { help } from "./helpers";

export function useBroken(): unknown {
  return { gone, alsoGone, styles, iconUrl, ambient, help };
}
