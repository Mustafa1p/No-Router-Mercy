# Third-party notices and provenance

The application uses Rust crates listed in `Cargo.toml`. `Cargo.lock` records the
resolved versions. Their respective licenses remain with their authors; this
document does not replace those licenses.

The UI uses eframe, egui and egui_extras. Networking uses reqwest and rustls;
other direct dependencies include crossbeam-channel, base64, serde, serde_json
and rfd. Review transitive dependencies as well before redistributing a release.

The existing source describes the router probes as clean-room implementations
from public advisories. `src/exploits.rs` cites Pedro Ribeiro / Agile InfoSec's
`pedrib/PoC` project and identifies that reference as GPLv3. Verify the provenance
and any resulting redistribution obligations before public distribution. No
claim that this audit has been completed is made here.

`docs/REFERENCE_SPEC.md` describes a separate Router Scan product. It is design
reference material, not an implementation checklist or a statement of features
available in this application. This project is not affiliated with that product.

The repository currently has no project-wide license grant. The owner must choose
a license after confirming rights to the source and the images in `src-media/`.
