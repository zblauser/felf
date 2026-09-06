# Baseline measurement — night 1

**Date:** 2026-08-19
**Question:** Does the industry-standard firmware SBOM toolchain miss things that matter?
**Method:** binwalk → unsquashfs → syft → grype on three OpenWrt 24.10.0 images.
**Why OpenWrt:** it ships `/usr/lib/opkg/status`, an authoritative record of what was
installed. Ground truth is inside the image. It is also the *best case* for syft, since
a readable package database exists. Vendor firmware without one should be worse.

## Raw results

| image | packages (truth) | syft artifacts | unique names | grype CVEs | kernel CVEs |
|---|---|---|---|---|---|
| tplink archer-c7-v2 (ath79) | 150 | 374 | 223 | 8 | 0 |
| xiaomi mi-router-4a (ramips) | 147 | 360 | 212 | 8 | 0 |
| raspberry pi 4 (bcm27xx) | 162 | 401 | 238 | 8 | 0 |

All three run Linux 6.6.73. All three report exactly 8 vulnerabilities, all in busybox.

## Finding 1 — artifact inflation (~2.5x)

Syft reports each opkg package twice: once from `/usr/lib/opkg/status`, once from
`/usr/lib/opkg/info/<pkg>.control`. 150 real packages → 300 "deb" artifacts, plus
kernel modules. It also mistypes opkg as `deb`.

Cosmetic on its own, but it means artifact counts in these SBOMs are not package counts,
and nobody reading the document would know that.

## Finding 2 — identity mismatch breaks vulnerability matching *(the important one)*

The SBOM is essentially complete by package count and still fails at its actual job,
because distro package identity ≠ upstream CVE identity.

**Verified case A — musl.** OpenWrt ships musl as a package named `libc`, version
`1.2.5-r4`. Confirmed musl by string in `/lib/libc.so` (`musl libc (mips-sf)`).
Syft emits `libc@1.2.5` with CPEs built from the name "libc". No musl CPE.
→ grype reports **0** CVEs.

**Verified case B — wpa_supplicant.** The binary `/usr/sbin/wpad` contains the string
`wpa_supplicant v2.12`. Syft lists the owning package as
`wpad-basic-mbedtls@2024.09.15~5ace39b0-r2` and generates 10 CPE permutations, none of
which reference wpa_supplicant. PURL is empty.
→ grype reports **0** CVEs.

**Control.** Same grype, same vulnerability database, same components — re-identified
with correct upstream CPEs:

| component | identifier used | CVEs found |
|---|---|---|
| musl 1.2.5 | `cpe:2.3:a:musl-libc:musl:1.2.5` | **3** (2 High, 1 Medium) |
| wpa_supplicant 2.12 | `cpe:2.3:a:w1.fi:wpa_supplicant:2.12` | **1** (High) |

CVE-2025-26519 (High), CVE-2026-40200 (High), CVE-2026-6042 (Medium), CVE-2024-5290 (High).

**Four real severity-rated vulnerabilities — three High — present in all three images,
reported as absent by the standard toolchain, purely because of naming.**

## Finding 3 — binwalk could not extract the filesystem

binwalk 3.1.0 on macOS failed on the squashfs in all three images
(`Extraction of squashfs data failed`). `unsquashfs` handled them fine after manual
carving. This is a missing `sasquatch` dependency, not a format problem — an environment
limitation, not evidence for the thesis. Recorded so it isn't mistaken for one later.

## What is NOT established

- **Kernel CVEs: inconclusive.** grype returned 0 for Linux 6.6.73 even when given the
  correct `cpe:2.3:o:linux:linux_kernel:6.6.73`. So the 0 in the table above is not yet
  attributable to identity mismatch. Needs separate investigation.
- **Static linking is untested.** The original thesis — components compiled in and
  therefore invisible — was not demonstrated. The string-based detector found only
  busybox, u-boot, and wpa_supplicant. OpenWrt links dynamically and packages everything,
  so it is the wrong corpus for that question. Needs vendor firmware.
- **n = 3, one distro, one version.** All three images share a build system, so these are
  three samples of one packaging behaviour, not three independent data points.

## Read

The night's result is not the thesis I started with — it's a better one.

The original pitch was *"your SBOM is missing components."* What's actually demonstrated
is *"your SBOM lists the components and still finds no vulnerabilities, because the names
don't resolve."* That is easier to prove, provable in 60 seconds, and applies even to
SBOMs that are complete.

It also reframes the product. The hard problem is not only extraction — it is
**resolution**: mapping whatever a component calls itself to the identity the vulnerability
databases use. That is a curated mapping asset that compounds, which is a better moat than
a parser.

## Next

1. Vendor firmware (no package database) — test the original static-linking thesis
2. Kernel matching — why does a correct kernel CPE still return nothing?
3. Buildroot and Yocto images — is this OpenWrt-specific or general?
4. Quantify: across N images, how many components resolve to a usable upstream identity?

---

> **!! CORRECTION — see part 4. The part 2 numbers below are WRONG.**
> The R7000 extraction was silently truncated (macOS case-insensitive filesystem collision
> on `libip6t_hl.so` vs `libip6t_HL.so`). Only 314 of 1564 files were written, 233 of them
> empty. syft was therefore scanning ~20% of the firmware. Corrected figures in part 4.

# Night 1, part 2 — vendor firmware

**Sample:** Netgear R7000, firmware V1.0.11.136_10.2.120 (~30MB, Broadcom, uClibc).
Downloaded from Netgear's own distribution server. No package database of any kind.

## Extraction

binwalk 3.1.0 on the shipped `.chk` file found **only container headers** — CHK and TRX —
and did not recurse into either. It reported no filesystem.

The rootfs was recovered by parsing the TRX header manually (partition offsets at bytes
16–28), carving partition 1, and running `unsquashfs`. Only then did 314 files and 46 ELF
binaries become visible.

**A practitioner following the standard workflow gets nothing from this file.**

## Component recall — the headline

| | count |
|---|---|
| Distinct upstream OSS projects present (by filename convention, conservative) | **25** |
| Reported by syft | **1** (busybox 1.22.1) |
| **Recall** | **4%** |

Present and entirely unreported: openssl, samba (85 shared objects), heimdal, curl,
uclibc, iptables (24 objects), zlib, talloc, tdb, tevent, ldb, libupnp, libmnl, ipset,
popt, pppd, pptpd, tcpdump, bzip2, lzop, hdparm, lsof, ntpclient, udev, gcc runtime.

Plus 12 vendor-proprietary blobs (libacos, libbcm, libnvram, libreadycloud…), which are
out of scope for OSS matching but in scope for the CRA technical file.

## Consequence — vulnerabilities

| scan | CVEs found |
|---|---|
| Standard toolchain (syft → grype) | **22** — all busybox |
| Adding **one** missed component (OpenSSL 1.0.2h) | **86** |

OpenSSL 1.0.2h alone contributes **64 CVEs: 4 Critical, 26 High, 31 Medium, 3 Low.**
Criticals include CVE-2016-2177, CVE-2016-2182, CVE-2016-6303, CVE-2024-5535.

That is the effect of identifying **one** of the twenty-four missed projects. Samba,
with 85 shared objects in this image, is not counted at all.

## Why versions are hard — and why that's the moat

Only OpenSSL carried a usable version string (`OpenSSL 1.0.2h` in `libcrypto.so.1.0.0`).
zlib, samba, curl, libupnp, iptables and tdb are stripped and yielded nothing to naive
string matching, even though their filenames name the project outright.

So the problem splits cleanly:

- **Which projects are present** — largely solvable from filenames and SONAMEs. Easy.
- **Which version** — requires real binary analysis. Hard.

The second half is the defensible part of the product, and it is exactly the
function-level fuzzy hashing work deferred to v2.

## Caveats

- One vendor image, one device. n=1 for the vendor case.
- Project count is by filename convention — a heuristic, though deliberately conservative
  (I did not count anything ambiguous).
- Versions are unproven for 24 of the 25 projects, so the 86-CVE figure is a floor from
  the one component I could version, not a total.
- The OpenSSL CVE list is unfiltered. Some will not be exploitable in this configuration —
  which is precisely what VEX is for, and precisely the product's second feature.
- Firmware dates to 2022; the R7000 is an older but still-supported consumer router.

## Revised read

Both theses now hold, in different corpora:

- **OpenWrt (package database present):** components are listed, but named such that
  vulnerability matching silently fails. 100% of CPEs merely permute the package name;
  67% have no PURL at all. The 8 CVEs found were found by naming coincidence.
- **Vendor firmware (no package database):** components are not listed at all. 4% recall.

Same product answers both. The unifying capability is **resolution** — determining what a
binary actually is and what upstream identity it maps to — not extraction.

---

# Night 1, part 3 — resolver prototype

Built `research/resolve.py`: a deliberately simple resolver testing how far the "easy half"
gets. Two signals only — filename/SONAME → upstream project identity, and embedded strings
→ version. No fuzzy hashing, no corpus, ~150 lines.

Then `research/compare.py` runs it end to end: resolver → CycloneDX with correct upstream
CPEs → grype, measured against the syft→grype baseline on the same image.

## Results

| image | components (syft) | components (resolver) | CVEs baseline | CVEs resolver | new | lost |
|---|---|---|---|---|---|---|
| archer-c7 (OpenWrt) | 223* | 11 | 8 | 9 | +1 High | 0 |
| ramips (OpenWrt) | 212* | 11 | 8 | 9 | +1 High | 0 |
| rpi4 (OpenWrt) | 238* | 12 | 8 | 9 | +1 High | 0 |
| **R7000 (vendor)** | **1** | **22** | **22** | **86** | **+64** | **0** |

\* syft's OpenWrt counts are inflated ~2.5x by double-counting and are package names, not
upstream identities — see part 1. The resolver reports upstream projects, so the numbers
are not directly comparable on OpenWrt; on the vendor image they are.

R7000 severity shift: Critical 3 → 7, High 13 → 39.

**Zero regressions on any image.** The approach is strictly additive — it never loses a
finding the baseline had.

## The design lesson that cost me a bug

First run showed no improvement on OpenWrt. Cause: the resolver mapped `libc.so.0` to
uClibc by filename. OpenWrt ships **musl**. Filename is ambiguous — `libc.so` could be
musl, uClibc, or glibc, and they are three different CVE identities.

Fixed by content inspection: look for `musl libc` / `uClibc` / `GNU C Library` markers in
the bytes and let content override filename. That immediately corrected musl and, with
`wpad` → wpa_supplicant added, surfaced the missing High CVE on all three images.

This is the thesis in miniature, again: **filenames get you candidates, content gets you
identity.** Any resolver built purely on naming convention will confidently produce wrong
answers. That is both the trap and the moat.

## Where the prototype is weak (honestly)

- **Versions:** 2 of 22 components versioned on the vendor image, 2 of 11 on OpenWrt.
  Stripped libraries yield nothing to string matching. This is the entire justification for
  the v2 fuzzy-hashing corpus, now empirically demonstrated rather than assumed.
- **No CVE lookup without a version.** 20 of 22 identified components on the R7000 contribute
  zero findings because we can't version them. The +64 comes from OpenSSL alone.
  A working version-identification stage plausibly multiplies that several times over.
- Filename rules are hand-written and will not generalize to unusual vendors.
- Vendor corpus is still n=1.

## Blocked: vendor firmware acquisition

Automated collection largely failed. dd-wrt sits behind an Anubis proof-of-work wall,
Netgear 403s directory listings (though direct file URLs work if you know the exact
filename), SourceForge 403s, ASUS and TP-Link guessed URLs 404.

Netgear R7000 succeeded only because the exact versioned filename was known.

**Needs a human with a browser.** Manually downloading 5-10 vendor images is a ~15 minute
task and is the single highest-value unblock for the writeup.

---

# Night 1, part 4 — CORRECTION and corrected vendor results

## What went wrong

The R7000 rootfs extraction failed silently. macOS uses a case-insensitive filesystem by
default; the firmware contains both `libip6t_hl.so` and `libip6t_HL.so`. `unsquashfs`
aborted on the collision:

```
FATAL ERROR: write_file: .../libip6t_hl.so already exists
```

It had already emitted a "created N files" line, so the failure looked like success.
Result: **314 of 1564 files written, 233 of them zero-length.** Every part-2 measurement
was taken against roughly a fifth of the firmware, with most binaries empty.

Caught only because the ELF reader reported `libz.so.1` and `libsamba-util.so.0` as
0 bytes.

**Fix:** extract onto a case-sensitive volume.
`hdiutil create -size 2g -fs "Case-sensitive APFS" -volname felf /tmp/felf.dmg`

Full extraction: 1564 files, 447 ELF binaries, 1 zero-byte.

## Corrected results — Netgear R7000, full extraction

| | part 2 (broken) | **part 4 (correct)** |
|---|---|---|
| files extracted | 314 | **1564** |
| ELF binaries | 46 | **447** |
| syft components | 1 | **3** (busybox 1.22.1, curl 7.36.0, openssl 1.0.2h) |
| syft→grype CVEs | 22 | **164** |
| resolver components | 22 | **24** (5 versioned) |
| resolver CVEs | 86 | **246** |
| **new CVEs found** | +64 | **+82** |
| regressions | 0 | **0** |

Severity shift: Critical 22 → **28**, High 65 → **99**.

Newly versioned once the files were actually present: **samba 4.4.3**, **zlib 1.2.5**,
**curl 7.36.0**.

## What the corrected numbers mean

**syft recall on vendor firmware: 3 of 24 = 12.5%.** Not the 4% I reported. syft's binary
classifiers do work — they found curl and openssl unaided once the bytes were there. The
earlier "syft found 1 component" claim was my bug, not syft's failure, and I retract it.

The finding that survives is still substantial and still commercially meaningful:

- syft identifies **3 of 24** upstream projects present (12.5%)
- the resolver finds **82 additional CVEs**, including **6 additional Criticals**
- **zero regressions** — strictly additive on every image tested
- Samba 4.4.3 (2016, 87 shared objects) is entirely absent from syft's output despite
  carrying a version string it could have read

## Lessons that belong in the product

1. **Silent partial extraction is a real failure mode**, and it produces confidently wrong
   SBOMs. The `coverage_gap` table in the architecture is not defensive over-engineering —
   I hit exactly this within one night. Extraction must verify inode count against files
   written and fail loudly.
2. **Case-insensitive host filesystems corrupt Linux firmware extraction.** The tool must
   detect this and either warn or use its own content-addressed store rather than the host
   filesystem — which is precisely what the architecture already specifies. That design
   choice just justified itself.
3. **Always validate the corpus before measuring against it.** I reported numbers from a
   broken tree. Cheap check: count zero-byte files after extraction.

---

# Night 1, part 5 — nested archives, build paths, and the corrected headline

## Two new resolution techniques, both validated

**1. Build-path mining.** Compilers embed `__FILE__` and debug paths; vendors rarely strip
them. Scanning for `/path/<project>-<version>/` recovered versions that string matching
missed entirely: iptables 1.4.12, pptpd 1.3.4, libmnl 1.0.3, ipset 6.29, libpcap 1.4.0.

One binary leaked `/home/tzhang/circle/ipset-6.29/src` — a developer's home directory,
shipped to customers. It also caught a **version skew inside one device**: userspace ships
ipset 6.29 while the kernel module ships 6.30.

**2. SONAME release-version extraction.** For *some* projects `libNAME.so.X.Y.Z` encodes
the upstream release (zlib, mbedTLS). For others it's an ABI number (curl, avahi, jansson).
This is per-project curated knowledge and getting it wrong **invents versions** — my first
pass emitted "avahi 5.3" and "jansson 11.1", both impossible. Caught and removed. Rules now
apply only where verified.

This is the clearest evidence yet that the moat is curated resolution knowledge rather than
parsing skill. The parser was easy; knowing which projects version their SONAME is the part
that takes work and the part that is wrong by default.

## The nested archive

`/opt/bit/bitdefender.tar` — **21MB of a 30MB firmware** — is a POSIX tar containing an
entire Bitdefender security suite: 312 files, 80 ELF binaries, a Rust application with
~31 crate dependencies, and its own complete set of shared libraries.

**syft scanned this directory and reported 0 components.** It does not recurse into the
archive, so two thirds of the firmware is simply not examined.

Inside it: Avahi, OpenSSL 1.0.2r, curl 7.61.1, libupnp 1.8.4, mbedTLS 2.13.0, libssh2,
jansson, zlib 1.2.8, uClibc-ng 1.0.22, strongSwan (`charon`), plus the Rust crate tree
(serde_json 1.0.48, chrono 0.4.10, rand 0.7.3, tar 0.4.26, uuid 0.7.4, nix 0.17.0, …).

## Duplicate components at different versions

The device ships **two vintages of three libraries simultaneously**:

| component | base firmware | Bitdefender bundle |
|---|---|---|
| OpenSSL | 1.0.2h | 1.0.2r |
| curl | 7.36.0 | 7.61.1 |
| zlib | 1.2.5 | 1.2.8 |

Any SBOM listing one entry per component is wrong about this device regardless of accuracy
elsewhere. Patching the base OpenSSL leaves the bundled one untouched.

## CORRECTED HEADLINE — Netgear R7000, full extraction, base + nested

| | components | CVEs | Critical | High |
|---|---|---|---|---|
| syft → grype | 3 | **164** | 22 | 65 |
| resolver | 17 versioned (+22 identified, unversioned) | **355** | 39 | 141 |
| **delta** | | **+146** | **+17** | **+76** |

**Zero regressions.** Strictly additive on every image tested.

Still unversioned and therefore contributing nothing: avahi, dnsmasq, hdparm, jansson, ldb,
libssh2, ntpclient, pppd, talloc, tcpdump, tdb, tevent, udev, wget. Versioning those is
further upside not counted above.

## Standing claim set (all verified tonight)

1. Vendor firmware, standard toolchain: **3 of ~24 components**, missing **146 CVEs**
   including **17 Criticals**.
2. Nested archives are invisible: **21MB / 70% of this firmware**, 0 components reported.
3. Distro-packaged firmware (OpenWrt): components listed but **100% of CPEs merely permute
   the package name**, 67% have no PURL. musl shipped as `libc`, wpa_supplicant as
   `wpad-basic-mbedtls`. Real CVEs silently unmatched.
4. Devices ship **duplicate components at different versions**; one-entry-per-component
   SBOMs cannot represent this.
5. Extraction fails silently and produces confidently wrong SBOMs (case-collision incident,
   part 4).

---

# Night 2 — second vendor image, and the CPE alias lesson

## TP-Link Archer C7 V5 (firmware 220715, 2022)

Processed end-to-end by `ingest.py` on first attempt: outer zip → 15MB `.bin` →
squashfs at offset 1167570 → 2387 files, 304 links, 4 zero-byte. No nested archives.

| | components | CVEs | Critical | High |
|---|---|---|---|---|
| syft → grype | 4 | **133** | 11 | 61 |
| resolver | 20 (14 versioned) | **225** | 19 | 91 |
| **delta** | | **+92** | **+8** | **+30** |

syft found: busybox 1.19.4, curl 7.79.1, openssl 1.0.2u, proftpd 1.3.4b.
Resolver additionally versioned: dnsmasq 2.83, hostapd 2.0, wpa_supplicant 2.0,
zlib 1.2.7, libpcap 1.1.1, **libssh 0.7.3**.

libssh 0.7.3 was found only by **build-path mining** (`libssh.so.4.4.1` carries no version
string). hostapd/wpa_supplicant 2.0 date to 2013.

## R7000 re-measured with the same pipeline

| | components | CVEs | Critical | High |
|---|---|---|---|---|
| syft → grype | 3 | **164** | 22 | 65 |
| resolver | 31 (24 versioned) | **332** | 46 | 129 |
| **delta** | | **+168** | **+24** | **+64** |

Higher than part 5's +146 because `ingest.py` now expands the nested Bitdefender archive
automatically and the alias table below recovers matches that were being dropped.

**Zero regressions on both images.**

## The CPE alias lesson — a real regression, caught and fixed

The Archer run initially showed **46 CVEs LOST** versus baseline — our first regression.

Cause: I emitted curl as `haxx:libcurl`. NVD files most curl CVEs under `haxx:curl`.
One wrong alias, 46 findings silently gone.

Fix: a curated `CPE_ALIASES` table emitting every known vendor:product pair per project
(curl → `haxx:curl`, `haxx:libcurl`, `curl:curl`; zlib → `gnu:zlib`, `zlib:zlib`,
`madler:zlib`; and so on).

The distinction that matters: syft **permutes the package name** and gets nothing;
we **enumerate known aliases** and get everything. Same output shape, completely different
epistemics. This is the curated-knowledge moat showing up for the third time tonight,
after SONAME-as-release and libc content disambiguation.

Also fixed: alias entries can match the same CVE more than once, so counts are now
deduplicated by CVE ID. Earlier un-deduped figures (460 / 265) were inflated;
correct figures are 332 / 225.

## Standing results — two vendors, two devices

| device | syft comps | syft CVEs | resolver comps | resolver CVEs | new | lost |
|---|---|---|---|---|---|---|
| Netgear R7000 | 3 | 164 | 31 | 332 | **+168** | 0 |
| TP-Link Archer C7 V5 | 4 | 133 | 20 | 225 | **+92** | 0 |

Consistent direction across two unrelated vendors, two SoC families, two build systems.

---

# Night 2, part 2 — five devices, three outcomes

| device | packaging | syft comps | syft CVEs | resolver comps | resolver CVEs | new | lost |
|---|---|---|---|---|---|---|---|
| Netgear R7000 | none | 3 | 164 | 31 (24 ver) | **332** | **+168** | 0 |
| TP-Link Archer C7 V5 | none | 4 | 133 | 20 (14 ver) | **225** | **+92** | 0 |
| ASUS RT-AC68U | .ipk files in /rom | 5 | 150 | 38 (31 ver) | **427** | **+277** | 0 |
| Ubiquiti EdgeRouter X | **Debian dpkg** | **838** | **1000** | 33 (9 ver) | — | — | — |
| Synology DS220j | **encrypted .pat** | — | — | — | — | — | — |

## Outcome A — vendor firmware with no package database (3 devices)

This is where the product lives. Consistent across three unrelated vendors and three SoC
families: syft sees 3-5 components, the resolver sees 20-38, and **zero regressions**.

ASUS is the largest delta yet: **+277 CVEs, Criticals 9 → 55.**

## Outcome B — Debian-based firmware: existing tooling already works

Ubiquiti EdgeRouter carries a real dpkg database with 365 packages. syft produced **838
artifacts, 100% of them with a PURL** (versus 33% on OpenWrt), and grype found 1000 CVEs
across 141 packages.

**We add little here and would lose a great deal if we replaced it.** This is an honest
scope boundary, and it directly contradicts an assumption I made on night 1 — that the
OpenWrt identity-mismatch failure would generalize to all package-managed firmware. It does
not. OpenWrt's opkg emits no PURLs and name-permuted CPEs; Debian's dpkg emits proper PURLs
that resolve correctly.

**Design consequence:** the tool must **union** its findings with the baseline scanner's,
never replace them. On Debian-based images we contribute almost nothing; on vendor firmware
we contribute most of the answer. Union is strictly correct in both cases.

## Outcome C — encrypted firmware cannot be analyzed at all

Synology `.pat` begins with magic `2dadbeef` and is an encrypted proprietary container. No
tooling can produce an SBOM from it without vendor keys.

This is a real category, and it maps onto CRA obligations: a manufacturer who cannot open a
supplier's binary must obtain the SBOM contractually. The tool's job is to say so clearly —
`coverage_gap: encrypted container, no analysis possible` — rather than emit a confident,
empty result.

## New resolution technique — package files shipped inside firmware

ASUS ships `.ipk` package files in `/rom`. The filenames are authoritative:
`asuslibcurl_7.24.0-1_arm.ipk`, `expat_2.0.1-1_arm.ipk`, `pcre_8.31-1_arm.ipk`,
`libevent_2.0.20-1_arm.ipk`, `ncurses_5.7-3_arm.ipk`.

Parsing them took ASUS from 7 versioned components to 31. Note `curl 7.24.0` — a 2012
release — in firmware ASUS published in May 2026.

Duplicate-version finding replicated: ASUS ships **openssl 1.0.2j AND 1.1.1n**, and
**curl 7.24.0 AND 7.84.0**.

## Second regression, caught and fixed

ASUS initially lost 44 CVEs: syft's binary classifier detected **ffmpeg** and my rules had
no media libraries at all. Added libav*/libsw* → ffmpeg, plus libpng, libjpeg-turbo,
freetype. Also normalized vendor version suffixes (`1.0.2j.v001` → `1.0.2j`).

Two regressions in two nights, both from *missing knowledge* rather than broken code —
first a CPE alias, then a whole component family. That is the shape of this problem, and it
is why union-with-baseline is a correctness requirement and not a nicety.

## Also fixed

Extraction completeness check was counting files and symlinks but not directories, so it
false-flagged Ubiquiti as incomplete (34,947 of 34,969 — the missing 22 are device nodes
`unsquashfs` skips without root). Threshold now counts dirs and allows 3%.

---

# Night 2, part 3 — own squashfs reader, and the D-Link corpus

## Corpus acquisition: I was wrong about "blocked"

Night 1 I reported automated firmware acquisition as blocked and needing a human. That was
true for two sources and false for three. The real obstacle is **filename discovery**, not
bot-blocking — vendor CDNs serve `curl` fine; the indexes are what's locked down.

Solved for: Synology (open `archive.synology.com` index → real CDN host), ASUS (exact URL
via search), Ubiquiti (predictable `dl.ui.com` path pattern).

Then found the big one: **`legacyfiles.us.dlink.com` is a fully browsable IIS index with
651 model directories** — routers, IP cameras, NAS, access points, switches, many with
10-30 firmware revisions each. `crawl_dlink.py` + `fetch_corpus.py` walk it and take the
newest per model. (Note: that server rejects `urllib` but serves `curl`.)

## The extraction wall — and our own reader

All six D-Link images failed extraction. Superblocks read fine; zero files came out.

Cause: **SquashFS with legacy LZMA1 compression.** Standard `unsquashfs` supports
gzip/xz/lzo/lz4/zstd but not the raw-LZMA1 variant Broadcom/Ralink-era vendors shipped.
binwalk delegates this to `sasquatch`, an unmaintained fork that isn't packaged (no brew
formula).

So I wrote `squashfs.py` — a SquashFS 4.0 reader with LZMA1 support.

The format detail that blocks every off-the-shelf tool: these blocks carry a **5-byte LZMA1
props header (props byte + dict_size) followed by a raw stream with no end marker and no
8-byte uncompressed-size field**. `lzma.decompress(FORMAT_ALONE)` rejects them because it
expects that size field. Parsing lc/lp/pb out of the props byte and feeding `FORMAT_RAW`
from offset 5 decodes them cleanly.

First test: 815 files, 96 dirs, 248 symlinks, **0 errors**, from an image binwalk could not
open at all.

This validates the architecture decision to own the parsers rather than shell out.

## Results — six devices with no usable package database

| device | class | syft | resolver | new CVEs | lost |
|---|---|---|---|---|---|
| Netgear R7000 | router | 3 comps / 164 | 31 / **332** | **+168** | 0 |
| TP-Link Archer C7 V5 | router | 4 / 133 | 20 / **225** | **+92** | 0 |
| ASUS RT-AC68U | router | 5 / 150 | 38 / **427** | **+277** | 0 |
| **D-Link DIR-655** | router | **0 / 0** | 19 / **226** | **+226** | 0 |
| **D-Link DNS-320** | NAS | 2 / 273 | 23 / **739** | **+466** | 0 |
| D-Link DAP-1522 | AP | 1 / 18 | 4 / **35** | **+17** | 0 |

**DIR-655: syft reports zero components and zero vulnerabilities.** A shipping consumer
router, and the industry-standard toolchain produces an entirely empty SBOM. We find 19
components and 226 CVEs, 22 of them Critical.

**DNS-320** is the largest absolute delta: **+466 CVEs**, Criticals 64 → 102. It ships
OpenSSL **0.9.7d** (2004), Samba 3.5.15, PHP 5.2.17 (2011), zlib 1.2.3, libpng 1.2.39.

Six devices, four vendors, four device classes, **zero regressions anywhere**.

## Third regression, same shape

DNS-320 initially lost all 273 baseline CVEs: syft's binary classifier found **php-cli
5.2.17** and my rules had no interpreters at all. Added php/perl/python/lua plus
vsftpd/minidlna/mt-daapd/transmission.

Three regressions now — curl CPE alias, ffmpeg, PHP — **all missing knowledge, none broken
code**. The union-with-baseline design rule is not optional; it is the only thing that makes
an incomplete knowledge base safe to ship.

## Still unextractable (3 of 9 D-Link)

COVR-1203, DCS-930L, DIR-868L — no filesystem found. Likely encrypted or a container format
not yet handled. Recorded as explicit coverage gaps, which is the correct behaviour.

## Storage

Corpus moved off iCloud to `~/fwcorpus` (symlinked from `research/firmware`). The fixed 12G
`.dmg` was replaced with a **sparse bundle** that grows on demand — reclaimed ~12G, free
space went 13Gi → 25Gi. `ingest.py` now prunes extracted rootfs after analysis by default
(`FELF_PRUNE=0` to keep them).

---

# Night 2, part 4 — what are we actually proving? (precision, and its limits)

## Scope discipline

We are **not** proving these routers are insecure. That is a twenty-year-old observation
and nobody pays for it.

We are **not** proving the reported CVEs are exploitable. They are unfiltered NVD matches
against version strings. "739 CVEs" on the DNS-320 means *739 CVE records match the versions
of components present* — not 739 ways in. The vulnerable feature may not be compiled; the
path may be unreachable. Filtering that is our own second feature (VEX), which means
leading with raw CVE counts is a claim our own roadmap undercuts.

The one thing the evidence supports:

> Given the same firmware file, the industry-standard SBOM toolchain and this resolver
> produce component inventories differing by 4x-19x, and in one case (DIR-655) the standard
> tool produces an entirely empty document.

That is verifiable by inspection, not judgment — the DIR-655 filesystem contains a file
named `libcrypto.so` and syft reports zero components. Under CRA/FDA a human signs that the
inventory is accurate, so an empty SBOM for a 19-component device makes that signature
false in a demonstrable way. **Tooling accuracy is the claim. Device security is not.**

## The unmeasured axis: precision

Everything measured so far is **recall**. "Zero regressions" only means we never lose a
baseline finding — it says nothing about whether our *additions* are right. For a compliance
product a wrong entry is worse than a missing one: it triggers unneeded remediation and
destroys trust on first check. And I have already caught this resolver inventing
`avahi 5.3` and `jansson 11.1`.

## Precision test, and why OpenWrt cannot answer it

`precision.py` scores blind resolver claims against `/usr/lib/opkg/status` (which the
resolver never reads). Result on two OpenWrt images:

| project | ours | opkg "ground truth" | verdict |
|---|---|---|---|
| busybox | 1.36.1 | 1.36.1-r2 | CORRECT |
| wpa_supplicant | 2.12 | 2024.09.15~5ace39b0-r2 | scored WRONG |
| mbedtls | 3.6.2 | — | unverifiable |

The `wpa_supplicant` row is **our answer being right and the ground truth being wrong**.
The binary's own string is `wpa_supplicant v2.12`; opkg's `2024.09.15~5ace39b0-r2` is a git
snapshot identifier for the `wpad-basic-mbedtls` package. My harness scored a correct answer
as an error.

**Conclusion: OpenWrt is unusable as ground truth for version precision**, because distro
package versions are not upstream versions — which is the night-1 finding restated, now
biting our own methodology.

Verifiable sample was 2 components per image. That is far too small to claim a precision
figure, and I am not going to quote one.

## Also exposed: version recall is weak where strings are absent

On OpenWrt we versioned 3 components while ground truth had 9+ available — we missed musl,
dnsmasq, dropbear, pppd, uhttpd, hostapd. Those binaries are stripped and their versions
exist only in the package database. Expected (syft already handles OpenWrt well), but it
confirms that string-based version extraction collapses without embedded version strings.
That is the fuzzy-hashing gap, now visible from a second direction.

## What would actually settle precision

Build firmware with **Buildroot or Yocto where we choose the component versions**, then run
the resolver blind against the resulting image. Ground truth is then exact, upstream, and
under our control — no distro renaming in the way. That is the ground-truth loop specified
in ARCHITECTURE and it is now the highest-value next experiment, ahead of corpus expansion.

**Until that exists, the honest claim set is:**
1. Recall gap vs standard tooling: measured, large, reproducible, 6 devices. SOLID.
2. Extraction gap (LZMA1 squashfs): measured, our reader opens what binwalk cannot. SOLID.
3. Precision of our version claims: **UNMEASURED**. Do not claim it.
4. Exploitability of reported CVEs: **NOT ASSESSED**, and not claimed.

---

# Night 2, part 5 — PRECISION MEASURED

## Method

OpenWrt could not settle precision (distro versions != upstream versions). Alpine can:
`.apk` filenames carry the **exact upstream version** (`curl-8.14.1-r2` -> curl 8.14.1).

`build_groundtruth.py` downloads 30 packages from two Alpine releases (v3.15 and v3.19, for
version spread), extracts the payloads, and **discards all package metadata** — no
`.PKGINFO`, no `lib/apk`, no `.apk` files left in the tree. Verified empty. The resolver
therefore sees only binaries and cannot cheat.

(Format note: `.apk` is three concatenated gzip streams — signature, control, data.
`tarfile` reads only the first, which is why the first attempt extracted nothing.)

`score_precision.py` then scores blind resolver output against the filename-derived truth.

## Result

| | Alpine 3.15 | Alpine 3.19 | combined |
|---|---|---|---|
| ground-truth components present | 25 | 25 | **50** |
| we produced a version for | 10 | 9 | **19** |
| of those, **correct** | 10 | 9 | **19** |
| **PRECISION** | **100%** | **100%** | **100%** |
| **VERSION RECALL** | 40% | 36% | **38%** |

**Every version claim the resolver made was correct. 19 of 19.**

Correct across: busybox, curl, dnsmasq, dropbear, expat, libpcap, libpng, lighttpd, openssl,
zlib — spanning both releases, so it tracked version *changes* correctly too (curl 8.5.0 vs
8.14.1, openssl 1.1.1 vs 3.1.8, dropbear 2020.81 vs 2022.83).

**Multi-version detection validated:** the 3.15 tree contains both OpenSSL 1.1.1w
(`libcrypto.so.1.1`) and 3.0.11 (`libcrypto.so.3`). The resolver reported both. This is the
duplicate-component behaviour we saw on the R7000 and RT-AC68U, now confirmed against known
ground truth rather than inferred.

## The failure mode is the right one

38% recall means we stay silent on ~6 of 10 components. Silence is a **declarable coverage
gap**; a wrong version is a **false statement in a signed declaration**. For a compliance
product those are not remotely equivalent, and this profile — never wrong, often silent —
is the one to have.

It also means the headline numbers on the vendor corpus are **floors, not estimates**.
The R7000's +168 and DNS-320's +466 were produced while versioning roughly a third of what
is present.

## What we still cannot version

avahi, bzip2, freetype, jansson, libjpeg-turbo, libssh2, libxml2, musl, ncurses, nghttp2,
openssh, pcre, sqlite, tcpdump, xz — 31 of 50. All stripped, none carrying a usable version
string. Exactly the fuzzy-hashing corpus work, now with a measured size: **it is worth
roughly 2.6x our current version yield.**

## Updated honest claim set

1. **Recall gap vs standard tooling** — measured, 6 devices, 4x-19x, zero regressions. SOLID.
2. **Extraction gap** — our LZMA1 squashfs reader opens firmware binwalk cannot. SOLID.
3. **Precision of version claims** — **100% on 19 claims against exact upstream ground
   truth.** MEASURED. Small sample; state the n.
4. **Version recall** — 38%. Known weakness, quantified, with a known fix.
5. **Exploitability of reported CVEs** — still NOT ASSESSED and still not claimed.

---

# v0.0.1 — Rust implementation begins

Workspace: `crates/core` (evidence model, content-addressed store), `crates/unpack`
(container peeling, filesystem detection, squashfs), `crates/cli`.

`felf unpack <image>` peels Netgear CHK and Broadcom TRX wrappers, locates filesystems by
signature, and extracts squashfs — both xz and **legacy lzma1**.

**Verified byte-for-byte:** D-Link DIR-655 yields 815 files, all 815 hash-identical to the
Python reference. That image is one `binwalk`/`unsquashfs` cannot open at all. R7000 (xz,
CHK+TRX wrapped) yields 1564 files, matching `unsquashfs`.

689 LOC, 1.2MB binary, clean clippy.

## The lzma1 detail worth remembering

Three approaches failed before the right one:

1. `lzma-rs` one-shot with a declared size — works for full 8192-byte metadata blocks,
   emits **nothing** for the short final block of a table.
2. `lzma-rs` `Stream` — only flushes at `finish()`, so a short block still yields nothing.
3. Binary-searching the true size — invalid: the success predicate is **not monotonic**
   (want=64 succeeded, 128 failed, 16 failed, 32 succeeded), because the stream flushes on
   internal buffer boundaries.

What works: splice a synthetic LZMA_alone header — the real 5 props bytes plus eight `0xFF`
bytes meaning "size unknown" — and hand it to liblzma, which decodes until input runs out.
That is the semantic this format needs and the one Python's `lzma` module was providing.

`xz2` exposes no raw-filter decoder, so the header splice is the route through its API.

## identify crate — graded

`crates/identify` ports the validated resolver: filename/SONAME rules, libc content
disambiguation, version-string patterns, build-path mining, package-filename parsing,
per-project SONAME-as-release, and the curated CPE alias table. Knowledge lives in
`rules.rs` as data, separate from the analyzer logic.

Graded against the same Alpine ground truth (`research/score_rust.py`):

| | python prototype | **rust** |
|---|---|---|
| precision | 100% (19/19) | **100% (21/21)** |
| version recall | 38% | **42%** |

Rust recall is higher because build-path mining runs inside the analyzer rather than as a
separate script — it picked up tcpdump on Alpine, and samba 3.0 / pcre 7.7 on the DIR-655
(both verified: `/samba-3.0/` in `nmbd`/`smbd`, `/pcre-7.7/` in the lighttpd modules).

Two scorer bugs found and fixed while grading, both the same class — a correct answer
scored wrong because the harness assumed one version per project:
- OpenWrt `wpad` (part 4): opkg's snapshot ID is not wpa_supplicant's upstream version.
- Alpine v3.15: the tree really does hold OpenSSL 1.1.1w *and* 3.0.11.

Ground truth is a project -> **set** of versions. Anything else penalises the
multi-version detection that vendor firmware actually requires.

## v0.0.1 — own LZMA1 decoder, tests, corpus bench

Replaced the `xz2`/liblzma dependency with our own LZMA1 decoder (~290 lines). Verified
byte-exact against a reference decode: DIR-655 yields 815 files, all identical.

One bug cost the afternoon and is worth recording: in the rep-distance shuffle,
`rep2 = rep1` must happen **only** when `IsRepG1 != 0`. Doing it unconditionally corrupts
`rep2` and every subsequent distance — output stayed correct for 262 bytes, then inserted a
single spurious byte and drifted. Symptom looked like truncation; cause was a one-line
control-flow error.

Corpus bench (`research/bench.py`) — 7 of 11 images extracted, 217 components, 127
versioned. Full table in `docs/PROOF.md`.

Two defects found by running the real binary across the corpus rather than one image:

- **Rust crates misidentified as C projects.** Build-path mining read
  `/root/.cargo/registry/src/.../curl-0.4.25/` and reported it as curl the C library.
  A cargo path names a crate whose CVE identity is `pkg:cargo/curl`, not `haxx:curl`.
  Now separated: crates get a `rust:` namespace and a cargo PURL, no C CPE. The prototype
  conflated these, so the Rust version is more correct here than its reference.
- **Zip parsing stopped at the first directory entry.** A zero-length member is not the end
  of an archive. TP-Link's zip leads with a directory entry, so the whole image fell through
  to a raw byte scan that matched a coincidental `hsqs`.

## Coverage and performance pass

**uImage support.** u-boot legacy images are peeled and their payloads decompressed
(none/gzip/LZMA). Critically the payload is an *additional* candidate, not a replacement:
a uImage kernel usually sits beside the rootfs rather than containing it, and substituting
it cost three images before the corpus bench caught it.

**Specific coverage gaps.** Encrypted containers are now recognised by magic (D-Link SHRS,
Synology `.pat`) or by entropy, and kernel-only images are named as such. Four corpus
images cannot be extracted and each now says why.

**cpio false positive.** Kernels embed the literal string `070701` in their own initramfs
parser diagnostics ("no cpio magic", "broken padding", "TRAILER!!!"). A signature match is
only believed if the 104 bytes behind it parse as hex.

**Performance: 5.7x.** Ubiquiti (21,803 files) went 56.5s -> 9.9s; ASUS 14.8s -> 3.6s.
Two causes, both in the squashfs reader: the metadata cache cloned an 8KB `Vec` on every
hit, and fragment blocks were re-decompressed once per file sharing them. Both now hand
back `Rc`. Extraction remains byte-identical (815/815 on DIR-655).

**A guard that was wrong.** Restricting build-path mining to ELF files looked like a
sensible optimisation and silently cost 31 components on the R7000 — the Rust crate paths
live inside `bitdefender.tar`, which is not an ELF. It contributed nothing to the speedup
either. Reverted. The corpus bench caught it; a single-image test would not have.

## emit — CycloneDX 1.6 and the HTML report

Components carry their evidence as `evidence.identity.methods` (technique, confidence,
source file), so any claim can be checked rather than trusted. CPE aliases ride as
properties; coverage gaps as `felf:coverage-gap` on metadata, since CycloneDX has no
field for "a region I could not read".

**Design correction found while testing:** a failed extraction used to bail with an error
and produce nothing. For an encrypted image the *useful* artifact is a document saying
"zero components, here is why" — that is what a manufacturer files. Now `scan` always
emits; only `unpack` errors.

## On selective decompression — rejected

Considered skipping files that "can't plausibly contain evidence" to cut scan time.
Rejected: it is the same reasoning as the `is_elf` guard that silently cost 31 components
on the R7000 hours earlier. Any skip rule is a guess about where evidence lives, and the
product claim is that we do not guess.

Compression also cannot be searched in place — LZMA/xz destroy the byte patterns being
matched, so finding a version string requires decompressing the block containing it.

The performance route is same work, less time: the `Rc` caching (5.7x, no coverage loss,
removed redundant work rather than necessary work), parallel file walking, and
Aho-Corasick to run all patterns in one pass instead of one regex pass per pattern.

## Quality pass

**Mutation testing.** 12,000 deterministic mutations (truncate, bitflip, insert, saturate)
across real and synthetic images, every parser exercised on each. Run in debug as well as
release so integer overflow panics rather than wrapping. The real corpus is also processed
by a debug build. No panics.

The harness asserts its own reach — filesystem matches, squashfs parses, LZMA bytes
decoded, archive members read. A fuzz test that never gets past an early return passes
while proving nothing, which is worse than no test.

**Zero `unwrap()` outside tests.** All binary reads now go through checked helpers in
`felf-core::bytes` (`le16/le32/le64/be32/find`), which also removed two duplicated
implementations: `find`/`find_bytes` were identical across crates, and raw `from_le_bytes`
with `.unwrap()` appeared 15 times beside checked helpers that already existed.

**`Box::leak` removed.** Component maps key on `String` rather than manufacturing
`&'static str` from runtime names.

**Dead code removed.** `Store::by_digest` was unused.

All verified no-ops: 217 components across the corpus, precision still 100%, DIR-655 still
815/815 byte-identical.

## Two precision bugs caught in a demo run

Both from build-path mining, both from the same root cause — the captured name excluded
hyphens.

- **`uclibc 4.5.3`.** Broadcom ships a toolchain directory named
  `hndtools-arm-linux-2.6.36-uclibc-4.5.3`. That version is the bundled GCC, not the libc.
  A toolchain directory is not the component it was built for.
- **Truncated crate names.** `num-integer-0.1.42` was reported as `integer`,
  `unicode-width-0.1.7` as `width`, `rustc-demangle` as `demangle`.

Allowing hyphens in the captured name fixed both: the toolchain path now captures
`hndtools-arm-linux-2.6.36-uclibc`, matches no known project, and is dropped.

Corpus versioned count went **127 -> 125**. That is the fix working — two wrong answers
removed. Fewer claims, all of them correct.

Regression tests added (`crates/identify/tests/buildpath.rs`) for the toolchain path, GCC
output directory, hyphenated crate names, cargo-vs-C identity, and that ordinary build-path
mining still works.

## Precision audit — four false positives found by reading output

Ran the analyzer over the corpus and audited which evidence kind supplied each version,
then checked the suspicious ones against the actual bytes.

**1. `uclibc 4.5.3`.** From Broadcom's toolchain directory
`hndtools-arm-linux-2.6.36-uclibc-4.5.3`. That version is the bundled GCC.

**2. Truncated crate names.** `num-integer-0.1.42` reported as `integer`. Same root cause
as (1) — the captured name excluded hyphens. Fixing that fixed both.

**3. `openssh 2.1` alongside `openssh 7.4`, from the same file.** sshd carries a
compatibility table of old releases for bug workarounds. Nothing in the bytes distinguishes
the binary's own version from a lookup string.

Rule added: **two versions from different files are two components; two versions from the
same file are contradictory evidence and yield no version.** A device really does ship two
generations of a library — the R7000 carries openssl 1.0.2h and 1.0.2r, and patching one
leaves the other exposed — so the distinction has to be by file, not by count.

**4. `perl 5.6`.** From a build path quoted inside
`usr/share/perl/5.24.1/TAP/Parser/SourceHandler/Perl.pm`. The containing path names the
real version, 5.24.1. A compiler embeds build paths in binaries; a source file quotes them
as content.

Rule added: no build-path mining on text files (>95% printable in the first 8KB).

**Refinements are not contradictions.** `libcrypto.so.1.0.2` yields `1.0.2` from a build
path and `1.0.2u` from a string. One refines the other; only the specific version is kept.
Without this the whole project was suppressed.

**Nested archives are now expanded.** 21MB of the R7000 is a single `bitdefender.tar`.
Scanning it as one blob both hid its contents and made the several versions it contains
look like contradictory evidence about one binary.

Net: corpus went 217 components / 125 versioned -> 206 / 108, and every removed claim was
one we could not defend. Precision still 100% on the ground-truth corpus. Nine regression
tests cover these cases.

**A correction I nearly made and shouldn't have.** `expat 1.95.2` looked like an ABI-tag
misread. It is not — that image genuinely ships `libexpat.so.0.1.0` containing
`expat_1.95.2`, while the DIR-655 ships `libexpat.so.1.5.2` containing `expat_2.0.1`. Old
firmware is old. Checking the bytes before "fixing" saved a correct answer.
