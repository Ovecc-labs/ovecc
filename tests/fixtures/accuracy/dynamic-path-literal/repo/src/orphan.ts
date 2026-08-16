// No import reaches it and no literal names it: genuinely dead, and the
// backstop must not swallow the true positive.
export function neverCalled(): string {
  return "orphan";
}
