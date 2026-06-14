# ovecc-git

## Purpose

`ovecc-git` reads Git history natively through `gix` (gitoxide). It never shells
out to a `git` process, so history extraction adds no subprocess overhead and has
no dependency on a `git` binary being installed. It supplies the temporal facts
the rest of the system layers on top of the static model.

## What it extracts

- **History** — recent commits and the files each one changed, over a bounded
  trailing window (current ownership does not need a decade of history).
- **Code churn** — modification frequency per file over that window, used by the
  hotspot score.
- **Ownership** — the majority contributor of each file plus its minor
  contributors. Fragmentation is measured with a concentration index: a file edited by many contributors with no clear majority
  is flagged as a knowledge-loss risk.
- **Ref resolution** — `resolve_ref` turns a branch, tag, SHA, or relative ref
  like `HEAD~1` into a commit SHA, which `diff` and `drift` use to compare two
  points in time.

## Place in the pipeline

The indexer calls into this crate during the analyze phase to ingest commits and
derive ownership, then persists both through `ovecc-db`. Repositories without Git
history still index fully; the temporal metrics are simply absent.
