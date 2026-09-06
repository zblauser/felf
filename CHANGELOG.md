# Changelog

Figures quoted here appear in `docs/PROOF.md`. Nothing is cited that is not measured there.

## v0.0.2 — 2026-09-01

This release adds a build-manifest comparison and makes felf read package databases
where firmware ships one. It also fixes a test that reported a pass without running,
and the documentation figures that had drifted from what the tool actually does.
Component output for images with no package database is byte-identical to v0.0.1.

### Added

- **`felf reconcile <image> --manifest <file>`** — compares what a build system says it
  shipped against what the image supports. Accepts Debian control, OpenWrt `name - version`
  manifests, and a generic two-column format, detected by content.

  The claim is **corroboration, not discrepancy**, and that was forced by the data. Deciding
  a declared package is *absent*, or a found component *undeclared*, needs a package-name to
  upstream-project mapping: 58 of the 140 entries in an OpenWrt manifest are `kmod-*` or
  `luci*`, and `kmod-ath9k - 6.6.73.6.12.6-r1` carries the kernel version, which is the
  `uclibc 4.5.3` mistake waiting to happen again. Debian supplies that mapping in `Source:`
  and nothing else does. So a manifest entry with no support is reported as unsupported, a
  component matching no entry is reported as a name that did not match, and neither is called
  a finding.

  Output separates corroboration from the bytes from corroboration by the image's own package
  database, because the database and the manifest are both products of the same build and
  agreement between them establishes very little. On the OpenWrt targets that split is 4
  against 136.

- Version handling is now format-aware. Stripping a trailing `-suffix` is Debian semantics;
  applied to a manifest of unknown provenance it would turn `1.0.2-beta1` into a claim about
  `1.0.2`. Control files strip the full revision, OpenWrt manifests strip only `-rN`, generic
  manifests strip nothing.

- `docs/PROOF.md` gains a **recall on real firmware** section. Binary evidence independently
  corroborates 4 of 140 declared packages on an OpenWrt image — and 4 of the 4 entries felf
  has any rule for. The limit is the 61-project curated table, not the technique. Published
  because it is what the measurement says.


- **felf reads opkg and dpkg databases.** `usr/lib/opkg/status` and `var/lib/dpkg/status`
  are Debian control files recording what the device believes it installed. felf ignored
  them entirely, which meant the most reproducible demo available — a public OpenWrt image
  anyone can download — was also its weakest result: 11 components, 3 versioned, while the
  image carried a database listing 150 packages at exact versions. It now reports 157
  components, 152 versioned, in 0.7s.

  Two rules keep the counts honest. Debian binary packages declare `Source:` when the
  upstream project is named differently, so `zlib1g` resolves to `zlib` on the database's
  own authority rather than a guessed alias table. And only the upstream part of a version
  is claimed — `1:1.2.8.dfsg-5` is zlib 1.2.8 — which also lets a database version match the
  one read out of the binary instead of reporting the library twice.

  This changed exactly one image of eleven in the vendor corpus: the Debian-based EdgeRouter
  X, 37 components to 271. Nothing else has a database. Counts derived from a database and
  counts recovered from binaries are different claims and the docs now say which is which.
  Known gap: a library named one way by the database and another by its binary still appears
  twice, as `openssl` and `openssl1.0` do on the EdgeRouter.

- A `Try it` section in the README with a public OpenWrt image, so every claim on the page
  is reproducible by a stranger in about a minute.

- `LICENSE` — the AGPL-3.0 text the README and `Cargo.toml` have always declared but the
  repository did not carry.
- `description`, `repository`, `readme` and `rust-version` in the package manifests.
- This file.

### Fixed

- **The accuracy gate could report a pass without running.** `precision_against_alpine_ground_truth`
  and `extracts_known_corpus_images` returned early and exited zero when `FELF_GROUNDTRUTH`
  or `FELF_CORPUS` was unset. Since the ground-truth volume is not mounted by default, the
  usual result was a green suite whose accuracy assertion had never executed. Both tests are
  now `#[ignore]`d — visibly not run rather than falsely passed — and panic with the missing
  variable named when invoked under `--ignored` without a corpus.

  The gate is now:

  ```
  FELF_GROUNDTRUTH=<ground truth root> FELF_CORPUS=<vendor firmware dir> \
  cargo test --release -- --ignored
  ```

- **Two corpus floors were stale and failing.** With the gate actually running,
  `extracts_known_corpus_images` failed: it required ≥24 components on the D-Link DNS-320
  (produces 22) and ≥40 on the Ubiquiti EdgeRouter X (produces 37). Those floors predate the
  precision audit that deliberately moved the corpus from 217 components / 125 versioned to
  206 / 108, removing every claim that could not be defended. The floors, not the analyzer,
  were wrong. Lowered to 20 and 35.

- **A corpus directory with no matching image counted as a pass.** A missing image is now a
  failure, so an empty or mistyped `FELF_CORPUS` cannot report success.

- **Every version of a duplicated component cited every other version's evidence.** The
  R7000 ships OpenSSL 1.0.2h in `lib/` and 1.0.2r inside `opt/bit/bitdefender.tar`.
  `build_components` cloned the project's whole evidence list onto both entries, so the
  1.0.2r component in the CycloneDX output was supported by `version-string: 1.0.2h` read
  from a file belonging to the other copy, and vice versa. Evidence is now attributed to
  the version its own file produced; evidence from a path that yielded no surviving
  version — a bare SONAME — stays on both, being a fact about the project rather than
  either copy. The R7000's two OpenSSL entries go from 14 identical methods each to 10 and
  4. Component output is unchanged; this only moves evidence between entries. It mattered
  because the duplicate-component finding is what the README leads with, and it was the
  one claim a reader could not check.

- **`docs/PROOF.md` figures had drifted** past the same precision audit: R7000 56 → 61,
  DNS-320 28/20 → 22/13, EdgeRouter X 47/22 → 37/10, totals 217/127 → 206/108. Also
  corrected the test and source-line counts.

- **README stated the precision sample wrongly.** "21 assorted firmware" described 21
  *version claims* graded against Alpine ground truth over a corpus of 7 vendor images.

- **`FELF_CORPUS` was documented one directory too high.** The Rust gate lists one level
  only and the images live in `vendor/`. Harmless while the test silently skipped; a hard
  failure now.

### Measured, and recorded so it is not re-derived

Extraction, not analysis, is 70–85% of a scan: R7000 4.29s total with 0.48s of analysis;
EdgeRouter X 10.32s total with analysis inside the noise of a 3.27s read. A planned parallel
walk and per-blob cache was dropped on these numbers — it targeted ~11% of runtime at best.
`felf unpack <dir>` loads only and `felf scan <dir>` loads and analyzes, so the pair
separates the two without instrumentation.

## v0.0.1 — 2026-08-24

First public tree. Single binary, no C dependencies.

- SquashFS (xz and legacy LZMA1) and cpio implemented directly, including an LZMA1 decoder,
  so D-Link images that `unsquashfs` cannot open are readable without `sasquatch`.
- Containers: zip, tar, gzip, Netgear CHK, Broadcom TRX, u-boot uImage, raw images.
- Component identification with evidence recorded for every claim — version string, build
  path, SONAME, package filename, and the file it came from.
- CycloneDX 1.6 SBOM (`--sbom`), self-contained HTML report (`--report`), coverage gaps
  emitted rather than dropped.
- 100% precision on 21 version claims against Alpine ground truth; 42% version recall.
