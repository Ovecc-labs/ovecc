# Cutting a release

1. Bump `version` under `[workspace.package]` in `Cargo.toml` (every crate
   inherits it via `version.workspace = true`).
2. Add a new `## [x.y.z] - YYYY-MM-DD` section at the top of `CHANGELOG.md`,
   above the current top entry. Its content becomes the GitHub release notes
   verbatim.
3. Commit and merge both changes to `main`.
4. Tag that commit and push the tag:

   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

CI re-runs `lint` + `build-test` + `self-review` on the tag, then
`release-version` verifies the tag matches `Cargo.toml`'s version, pulls the
matching `CHANGELOG.md` section as notes, and publishes the versioned GitHub
release with the Linux + Windows binaries attached.

Every push to `main` also republishes a rolling pre-release, `latest`, with
fresh binaries — no tag needed for that one.
