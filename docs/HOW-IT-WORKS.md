# How felf works

A firmware image goes in. A component inventory with evidence comes out. Four stages.

---

## 1. Unwrap

Vendors nest. A typical path is `zip → Netgear CHK header → Broadcom TRX partition table →
SquashFS`, and a u-boot uImage may sit alongside the filesystem or contain it.

`felf` peels each layer and, importantly, treats a uImage payload as an **additional**
candidate rather than a replacement. A kernel usually sits beside the rootfs rather than
containing it; substituting it once cost three images in our corpus before the corpus test
caught it.

Filesystems are located by signature scan rather than by trusting a header, because vendor
images routinely disagree with their own metadata.

## 2. Extract

**SquashFS is implemented directly**, including the legacy **LZMA1** variant.

This matters more than it sounds. `unsquashfs` supports gzip, xz, lzo, lz4 and zstd, but not
the raw-LZMA1 form that Broadcom and Ralink-era vendors shipped. `binwalk` delegates that
case to `sasquatch`, an unmaintained fork with no Homebrew package. Six of nine D-Link
images in our corpus use it — the industry-standard toolchain cannot open them at all.

The format detail that defeats off-the-shelf decoders: these blocks carry a **5-byte LZMA1
header (properties + dictionary size) followed by a raw stream with no end marker and no
uncompressed-size field.** Decoders that require a declared length emit nothing for the
short final block of a metadata table. `felf` ships its own LZMA1 decoder (~290 lines, no C
dependency) which simply decodes until the input runs out.

Extraction is verified: on the DIR-655 it produces 815 files, all 815 byte-for-byte
identical to a reference decode.

Nested archives inside the rootfs are expanded too. 21MB of the Netgear R7000 — about 70% of
the image — is a single `bitdefender.tar`. Treating it as one file both hides its contents
and makes the several component versions inside it look like contradictory evidence about
one binary.

## 3. Identify

Six independent signals, each producing **evidence** rather than an assertion:

| signal | example |
|---|---|
| version string | `OpenSSL 1.0.2h` in `libcrypto.so` |
| build path | `/home/dev/ipset-6.29/src` embedded by the compiler |
| SONAME | `libz.so.1.2.8` — but only where a project versions its SONAME by release |
| package filename | `expat_2.0.1-1_arm.ipk` shipped in `/rom` |
| content marker | `musl libc` vs `uClibc` inside a file named `libc.so` |
| package database | `opkg`, `dpkg` where present |

**The package database is used where it exists, and usually it does not.** `usr/lib/opkg/status`
and `var/lib/dpkg/status` are the device's own record of what was installed, which beats
anything inferred from bytes. Two details keep it from inflating the count: a Debian binary
package declares `Source:` when the upstream project is named differently, so `zlib1g`
resolves to `zlib` on the database's own authority rather than a guessed alias; and only the
upstream part of the version is claimed, so `1:1.2.8.dfsg-5` is zlib `1.2.8` — which is also
what lets a database version match the one read out of the binary instead of reporting the
same library twice. Across eleven vendor images exactly one had a database.

**Build-path mining** is the highest-yield signal and the easiest to get wrong. Compilers
embed `__FILE__` and debug paths and vendors rarely strip them, so a source directory often
carries a version no string table exposes. One binary shipped
`/home/tzhang/circle/ipset-6.29/src` — a developer's home directory, in a consumer product.

It only applies to binaries. A path quoted inside a text file is content, not provenance:
`usr/share/perl/5.24.1/.../Perl.pm` mentions `/perl-5.6/`, and the containing path names the
real version.

**Cargo registry paths name Rust crates, not the C projects they share names with.** The
`curl` crate at 0.4.25 is `pkg:cargo/curl`, not `cpe:2.3:a:haxx:curl` — conflating them
invents vulnerabilities.

## 4. Resolve

Turning "this is OpenSSL 1.0.2h" into something a vulnerability database will match is where
most of the difficulty lives, and where most tools quietly fail.

**Names are not identities.** OpenWrt ships musl as a package called `libc` and
wpa_supplicant inside one called `wpad-basic-mbedtls`. A scanner that emits those names
finds zero vulnerabilities in either, because nothing in NVD is filed under them.

**One project has several identifiers.** NVD files curl under `haxx:curl`, `haxx:libcurl`
and `curl:curl`. Emitting only one loses findings — in our case 46 CVEs. `felf` carries a
curated alias table and emits every known pair. The distinction that matters: other tools
**permute** the package name and match nothing; this **enumerates known aliases**.

**Two versions mean different things depending on where they came from.**

- Different files → two components. The R7000 genuinely carries OpenSSL 1.0.2h and 1.0.2r,
  and patching one leaves the other exposed.
- The same file → contradictory evidence. `sshd` carries a compatibility table of old
  OpenSSH releases; nothing in the bytes says which string is the binary's own version. In
  that case felf reports the component as present with **no version**.
- One a prefix of the other → a refinement, not a conflict. A build path often carries the
  release series while the binary carries the point release; only the specific one survives.

## 5. Emit

CycloneDX 1.6. Each component carries `evidence.identity.methods` — technique, confidence,
and the file the claim came from — so any assertion can be checked rather than trusted.
Additional CPE aliases ride as properties.

Coverage gaps are emitted as `felf:coverage-gap` properties on metadata. CycloneDX has no
field for "a region I could not read", and omitting them makes an incomplete document look
complete.

**An image that cannot be opened still produces a document** — zero components and a stated
reason. For encrypted firmware that is the useful artifact, and an error message is not.

---

## Why precision over recall

Roughly six components in ten are identified but not versioned **in an image with no
package database**, which is most of them. Where a database exists the picture inverts — a
public OpenWrt image comes back 152 versioned of 157. That is a deliberate position, not a
limitation being apologised for.

An unversioned component is a **declarable coverage gap**. A wrong version is a **false
statement in a signed declaration**. Those are not equivalent, and for a document that
carries a person's name they are not close.

Accuracy is measured, not asserted: graded against Alpine packages whose filenames carry
exact upstream versions, with all package metadata stripped so the analyzer works from
binaries alone. 21 of 21 version claims correct. A test ratchet fails if that regresses;
it is `#[ignore]`d by default because the corpus cannot be shipped, so it runs under
`cargo test --release -- --ignored` and fails rather than skips when the corpus is absent.

## Robustness

Every parser reads attacker-controlled bytes, so malformed input must produce a wrong
answer or no answer, never a crash. 12,000 deterministic mutations — truncation, bit flips,
insertion, saturation — across real and synthetic images, run in debug as well as release so
integer overflow panics rather than wrapping silently.

The harness asserts its own reach by counting filesystem matches, SquashFS parses, LZMA
output bytes and archive members. A fuzz test that never gets past an early return passes
while proving nothing, which is worse than no test.
