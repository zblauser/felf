# felf — proof of viability

*firmware component inventory · reads what the vendor shipped, claims only what it can prove*

v0.0.2 · single binary, no C dependencies · accuracy enforced by a test ratchet

## Claim

> Given the same firmware file, the industry-standard SBOM toolchain and felf produce
> component inventories that differ by several times over — and on some devices the
> standard tool produces an empty document.

Verifiable by inspection: the DIR-655 filesystem contains a file named `libcrypto.so`,
and syft reports zero components.

## Corpus results

Real firmware, downloaded from vendor distribution servers. `syft` column is unique
component names from the industry-standard toolchain (binwalk → syft) on the same image.

| device | class | files | felf components | versioned | syft |
|---|---|---|---|---|---|
| Netgear R7000 | router | 1564 | **61** | 43 | 3 |
| ASUS RT-AC68U | router | 2449 | **41** | 21 | 5 |
| D-Link DNS-320 | NAS | 2739 | **22** | 13 | 2 |
| TP-Link Archer C7 V5 | router | 2090 | **22** | 10 | 4 |
| **D-Link DIR-655** | router | 815 | **19** | 9 | **0** |
| D-Link DAP-1522 | access point | 763 | 4 | 2 | 1 |
| Ubiquiti EdgeRouter X | router (Debian) | 21803 | 271 | 258 | **838** |

7 of 11 images extracted. **Six carry no package database and every component in those
rows was identified from the bytes: 169 components, 98 versioned.** The EdgeRouter ships a
Debian `dpkg` database, which felf reads: 271 components, 258 versioned, most of them from
that file. Totals across all seven are 440 and 356, but a count read out of a database and a
count recovered from binaries are not the same claim and should not be added together
without saying so.
Scan times: 4.2s for a 30MB router image, 10.4s for a 70MB Debian router image with 21,803
files, 0.7s for a 6.6MB OpenWrt image. Roughly 70-85% of that is filesystem extraction, not
analysis.

**Ubiquiti is the honest counter-example.** It carries a real dpkg database, existing
tooling already works there, and we add little. The product's value is concentrated on
firmware without a usable package database — which is most consumer and embedded devices,
but not all of them.

## The four that did not extract — and why that is an answer, not a failure

Each reports a specific reason rather than an empty result:

| device | reported gap |
|---|---|
| Synology DS220j | `Synology encrypted .pat — encrypted, no key supplied` |
| D-Link COVR-1203 | `D-Link SHRS encrypted container — encrypted, no key supplied` |
| D-Link DIR-868L | `high entropy throughout, no parseable structure — likely encrypted` |
| D-Link DCS-930L | `uImage@0x50000 decompressed but contains no filesystem — kernel-only image` |

Three are encrypted. That does not mean unopenable: public keys exist for several D-Link
SHRS models, `syno-extract-system-patch` handles a range of DSM releases, and vendors
sometimes ship an unencrypted earlier firmware whose bootloader carries the key. The
accurate claim is narrower — **we cannot open these from the information in the file
alone**, and no key was supplied. Accepting user-supplied keys is a planned feature.

It still maps onto a real CRA obligation: a manufacturer who cannot open a supplier's
binary has to obtain the SBOM contractually. The fourth image genuinely ships no root
filesystem.

"I could not open this, and here is precisely why" is a usable statement in a compliance
document. "No components found" is not.

## Extraction capability others lack

D-Link firmware uses **SquashFS with legacy LZMA1**. `unsquashfs` does not support it;
binwalk delegates to `sasquatch`, an unmaintained fork with no package in Homebrew.

felf ships its own LZMA1 decoder (`crates/unpack/src/lzma.rs`, ~310 lines, no C
dependency). On the DIR-655 it produces **815 files, all 815 byte-for-byte identical** to
a reference decode.

## Package databases, where they exist

opkg and dpkg record what the device believes it installed, in Debian control format. felf
reads `usr/lib/opkg/status` and `var/lib/dpkg/status` and reports those entries at
`Confirmed` with evidence kind `package-database`.

Two rules keep that honest rather than inflationary:

- **The database names its own upstream project.** A Debian binary package declares
  `Source:` when it differs from the package name — `zlib1g` declares `Source: zlib`. felf
  uses that field rather than a curated alias table, because guessing aliases is how this
  project previously invented `avahi 5.3`. Without it the EdgeRouter reported `zlib 1.2.8`
  and `zlib1g 1.2.8.dfsg-5` as two separate components.
- **Only the upstream part of the version is claimed.** A Debian version is
  `[epoch:]upstream[-revision]`; opkg appends `-rN`. `1:1.2.8.dfsg-5` is a claim about
  zlib 1.2.8, and reporting the packaging string would both overstate what is known and stop
  the database version matching the `1.2.8` read out of the binary.

Effect on the corpus: **one image of eleven changed.** The EdgeRouter went from 37
components to 271. Nothing else moved, because nothing else has a database — which is the
premise of the tool, now measured rather than asserted. On a public OpenWrt image the same
change took 11 components to 157.

**Known limitation.** Where a library is named one way by the database and another way by
its binary, both entries survive: the EdgeRouter reports `openssl 1.0.2u` from binary
evidence and `openssl1.0 1.0.2u` from its dpkg entry. That is one library counted twice.
Reconciling the two sources against each other is not implemented.

## Measured accuracy

Graded against Alpine packages, whose filenames carry exact upstream versions. All package
metadata is stripped from the test tree, so the analyzer works from binaries alone.

| | |
|---|---|
| ground-truth components | 50 |
| version claims made | 21 |
| **claims correct** | **21** |
| **precision** | **100%** |
| version recall | 42% |

**Every version claim was correct.** The failure mode is silence, not error — which is the
right one: silence is a declarable coverage gap, a wrong version is a false statement in a
signed declaration.

Enforced by a test ratchet: the precision assertion fails if any claim is wrong, and if
version recall drops below 40%. It carries `#[ignore]` because the ground-truth corpus is
too large to ship, so the gate is `cargo test --release -- --ignored` with
`FELF_GROUNDTRUTH` set. Asked for without a corpus it fails rather than skipping — a gate
that reports a pass without running is worse than no gate.

## Recall on real firmware

The 42% above is measured against a synthetic Alpine tree assembled for the purpose. Real
firmware asks a harder question, and `felf reconcile` answers it by comparing a build
manifest against what the image supports. Three OpenWrt 24.10.0 targets, each against the
manifest published beside it:

| target | declared | corroborated from the bytes |
|---|---|---|
| ath79 generic | 140 | 4 |
| ramips mt7621 | 126 | 4 |
| bcm27xx bcm2711 | 134 | 4 |

The same four every time: busybox, dnsmasq, dropbear, uhttpd. Read against three
denominators, because the choice of denominator decides the answer:

| denominator | ath79 |
|---|---|
| every manifest entry | 4 / 140 |
| excluding 58 `kmod-*` and `luci*` entries | 4 / 82 |
| entries matching a project felf has a rule for | **4 / 4** |

**The limit is coverage, not technique.** `rules::CPE` carries 61 projects, and only four of
the 140 things this image declares are among them — the rest are OpenWrt's own furniture
(`ubus`, `netifd`, `uci`, `procd`, kernel modules, LuCI) with no upstream CPE identity.
Every declared package felf had a rule for, it corroborated from the bytes.

Three things that keep this from being a better number than it is:

- **Four is a tiny sample**, and the same curated table decides both what felf looks for and
  what counts as findable. 4/4 is not a claim about accuracy.
- **Most corroboration is close to circular.** 136 of 140 entries were corroborated only by
  the image's own opkg database, which is a product of the same build as the manifest.
  `reconcile` counts that separately and says so on its own output.
- **Three of the four are corroborated by SONAME**, which establishes presence rather than
  version. Only busybox carries a version string felf reads out of the binary.

The honest summary: on a distro-style image, binary evidence independently recovers very
little, because most of what is installed is not a component anyone files a CVE against. The
lever is the size of the curated project table, which is bounded, checkable work.

## What is not claimed

- **Not** that these devices are exploitable. Component versions are matched against CVE
  records; whether a vulnerable path is reachable is a separate question we do not answer.
- **Not** that the inventory is complete. 42% version recall means most components are
  identified but unversioned, and unversioned components yield no findings.
- Precision is measured on 21 claims. That is a real number, not a large one.

## Output

`--sbom` writes CycloneDX 1.6. Every component carries its evidence as
`evidence.identity.methods` — technique, confidence, and the file the claim came from — so
a reader can check any assertion rather than taking it on trust. Additional CPE aliases
ride as `felf:cpe-alias` properties, because NVD files one project under several
vendor:product pairs and a consumer matching only on `cpe` loses findings.

Coverage gaps are emitted as `felf:coverage-gap` properties. CycloneDX has no native
field for "a region I could not read", and omitting them would make an incomplete document
look complete.

**An image that cannot be opened still produces a document** — zero components and a stated
reason. For an encrypted image that is the useful artifact, and an error message is not.

`--report` writes a self-contained HTML page: the delta against the customer's existing
SBOM, the component table with evidence, the coverage gaps, and a footer stating plainly
that this is an inventory and not a vulnerability assessment.

## Robustness

Every parser here reads attacker-controlled bytes, so malformed input must produce a wrong
answer or no answer — never a panic.

`crates/unpack/tests/robustness.rs` mutates real and synthetic images (truncation, bit
flips, insertion, saturation) across 12,000 deterministic seeds and runs all parsers over
each. The harness asserts it *reached* the parsers — a fuzz test that never gets past an
early return proves nothing — by counting filesystem matches, squashfs parses, LZMA output
bytes, and archive members.

Run in debug as well as release, so integer overflow panics instead of wrapping silently.
The full vendor corpus is also processed by a debug build.

Zero `unwrap()` outside tests; all binary reads go through checked helpers in
`felf-core::bytes`.

## Test suite

44 tests, zero clippy warnings, 2701 lines of source. Forty-one run on a bare
clone; the three that need vendor firmware, an OpenWrt image or the ground-truth corpus are
`#[ignore]`d and reported as ignored rather than passed.

- LZMA1 decoder vs embedded reference block (byte-exact), output limits, truncated input,
  invalid props, garbage input
- Container peeling: TRX, CHK→TRX, passthrough, filesystem signature detection
- Precision ratchet against Alpine ground truth
- Corpus extraction floors — catches a change that helps one image while breaking others
- Reconcile against a published OpenWrt manifest, holding the corroborated-from-bytes split

## Reproduce

```
cargo test --release
FELF_GROUNDTRUTH=<ground truth> FELF_CORPUS=<vendor firmware> FELF_OPENWRT=<openwrt images> \
  cargo test --release -- --ignored
cargo run --release -p felf-cli -- scan <firmware>
```
