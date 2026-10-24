# Contributing

Open an issue with a reproducible problem, expected behavior, Windows version and
application version. Remove credentials, real device identifiers and private scan
results from reports. Use local fixtures or devices you are authorized to test.

Install Rust using the checked-in toolchain and Visual Studio C++ Build Tools
with the Windows SDK and x86/x64 tools. Before opening a pull request, run:

```powershell
cargo fmt --all -- --check
cargo clippy --locked --all-targets
cargo test --locked
cargo build --release --locked
```

Keep changes focused. Explain user-visible behavior and validation. Add regression
coverage for parser, scan coordination or persistence changes. Tests must not
contact public routers or depend on access to the internet.

Keep generated binaries, credentials, local configuration and scan exports out of
commits. Update the README and changelog when behavior changes. See
[release instructions](docs/RELEASING.md) for packaging.
