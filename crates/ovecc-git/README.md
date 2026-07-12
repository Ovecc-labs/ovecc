# ovecc-git

Native Git history through `gix` (gitoxide): no shelling out, no dependency
on an installed `git` binary. It supplies the temporal facts the rest of the
system layers on top of the static model.

It extracts recent commits and the files each one changed, over a bounded
trailing window (current ownership does not need a decade of history);
per-file churn, which feeds the hotspot score; and per-file ownership, the
majority contributor's share plus the count of minor contributors, so a file
edited by many hands with no clear majority is flagged as a knowledge-loss
risk. `resolve_ref` turns a branch, tag, SHA, or relative ref like `HEAD~1`
into a commit SHA, which `diff`, `drift`, and `review` use to compare two
points in time.

The indexer ingests commits and derives ownership during the analyze phase,
then persists both through `ovecc-db`. Repositories without Git history
still index fully; the temporal metrics are simply absent.
