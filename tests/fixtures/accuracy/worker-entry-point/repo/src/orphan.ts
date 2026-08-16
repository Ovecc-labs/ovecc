// Genuinely unreachable: no import, no worker spawn, no literal names it.
// Widening reachability must not cost the true positive.
export function neverCalled(): string {
  return "orphan";
}
