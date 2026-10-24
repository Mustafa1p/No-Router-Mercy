# Releasing No Router-Mercy

## Prepare

1. Confirm source and artwork provenance, select a project license, and review
   `THIRD_PARTY_NOTICES.md` before public redistribution.
2. Update `Cargo.toml`, `CHANGELOG.md` and README download examples together. The
   window title and Windows executable resource version derive from Cargo metadata.
3. Run formatting, Clippy and tests for both Windows targets. Build packages using
   `scripts/package-windows.ps1 -Architecture x86` and `-Architecture x64`.
4. Test installation, launch, settings persistence, upgrade and uninstall in clean
   Windows environments. Test the x86 build on a 32-bit Windows environment as well.
   Confirm the ZIP launches after extraction. Review dependency and signing needs.

## GitHub

Commit source, documentation, assets and `Cargo.lock`. Do not commit setup files,
executables, `target/`, local settings, credential files or scan results.

```powershell
git add .
git commit -m "Prepare Windows release and GitHub project"
git push origin HEAD
git tag -a v0.1.0 -m "No Router-Mercy 0.1.0"
git push origin v0.1.0
```

The tag must equal `v` followed by the Cargo package version. GitHub Actions builds
x86 and x64 packages from the tagged commit, tests both and attaches the installer,
portable ZIP and checksum files to a draft release. Review artifacts and release
notes before manually publishing the draft. Keep GitHub Actions enabled and allow
the workflow's release job to write repository contents.

For a rehearsal, manually run the Windows release workflow. It uploads artifacts
without creating a GitHub release. Local package output defaults to the sibling
`No-Router-Mercy-releases` directory.

## Validation boundaries

Successful compilation and unit tests do not replace testing on a clean Windows
installation. Local unsigned builds have no publisher identity. Add a signing
step with protected credentials if distributing signed installers. Never commit
certificates, signing passwords or release credentials.

The previous local build caches, settings and executable were moved to the sibling
`No-Router-Mercy-local-artifacts` directory during repository cleanup. That folder
is outside the repository and is not part of a release.
