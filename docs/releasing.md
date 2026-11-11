# Release guide

These are development packages, currently version 0.3.0. Repository names match
crate names under https://github.com/buntrail. No publication is automated.

Publish in order: buntrail-core; buntrail-language, buntrail-protocol and
buntrail-services; buntrail-helper; buntrail-engine; buntrail-ffi. Wait for each
prerequisite version to appear in the crates.io index before the next step.
Engine integration tests need the matching helper executable.

For each repository, create your Git repository, commit the reviewed source and
push it to its matching public GitHub repository. Verify the crate name is
available (names have not been reserved). Then run:

```sh
cargo fetch
scripts/check.sh
cargo package --list
cargo publish --dry-run
# Review the archive, metadata, tests and license notices before publishing:
cargo publish
```

Commit the resulting Cargo.lock for reproducible developer checks, especially
for executable packages. Do not copy a parent workspace lockfile containing local
patches and call it registry verification. Tag the published commit v0.3.0 and
update CHANGELOG.md. Re-run the dry run after any change.

Before the first publication, dependent repositories cannot resolve unpublished
Buntrail versions from crates.io. The parent workspace uses local Cargo patches
but registry packaging of dependents still needs their prerequisites published. Extracted-source checks with explicit
patches are integration evidence, not a registry-only dry run. Do not bypass
verification with --no-verify to claim readiness.
