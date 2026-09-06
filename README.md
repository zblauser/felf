# felf

**Firmware component inventory. Reads what the vendor actually shipped, and claims only what it can prove.**

Point it at a firmware image. It tells you which upstream open source components are inside (at which versions), with the evidence for every claim. It then tells you plainly about anything it could not read.

<p align="center"><img src="assets/extract.gif" alt="binwalk cannot open the image; felf reads it" width="88%"/></p>

---

Firmware is assembled from hundreds of pieces of open source code. Regulators now require it to be: under the EU Cyber Resilience Act, from 11 December 2027, you cannot sell a product with software in it into the EU without a software bill of materials. The FDA already requires one for medical devices. In both cases a person signs a declaration that the inventory is accurate.

The standard toolchain: `binwalk` into `syft` into `grype`, was built for software that declares its own dependencies. Firmware however does not. C and C++ components are compiled straight into the binary, often lack package databases, and much of the image is often locked inside a nested archive nobody opens.

So a document gets produced, may look complete, and is not.

## Tests

Real firmware, downloaded from vendor distribution servers. `syft` is the industry standard tool, run on the same image.

| device | class | files | felf | versioned | syft |
|---|---|---|---|---|---|
| Netgear R7000 | router | 1564 | **61** | 43 | 3 |
| ASUS RT-AC68U | router | 2449 | **41** | 21 | 5 |
| D-Link DNS-320 | NAS | 2739 | **22** | 13 | 2 |
| TP-Link Archer C7 V5 | router | 2090 | **22** | 10 | 4 |
| **D-Link DIR-655** | router | 815 | **19** | 9 | **0** |
| D-Link DAP-1522 | access point | 763 | 4 | 2 | 1 |
| Ubiquiti EdgeRouter X | router (Debian) | 21803 | 271 | 258 | **838** |

The DIR-655 is the obvious case: standard toolchain produces entirely empty document for a shipping consumer router.

**Two of those numbers are not the same kind of number.** Six of these images carry no package database, so every component in those rows was identified from the bytes: 169 components, 98 versioned. The EdgeRouter is the exception — it ships a Debian `dpkg` database, felf reads it, and most of its 271 come from that file rather than from analysis. Counting a database is easy. Say which you did.

The EdgeRouter remains the honest counter example. Existing tooling already works well there and syft still reports more than felf does. This is a tool for firmware **without** a usable package database — most current consumer and embedded devices — and where one exists felf reads it rather than pretending it does not.

## Try it

The comparison above uses vendor firmware you would have to source yourself. This one you can run in a minute:

```
curl -O https://downloads.openwrt.org/releases/24.10.0/targets/ath79/generic/openwrt-24.10.0-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin
felf scan openwrt-24.10.0-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin
```

```
no wrapper  1086 files (925 unique)  squashfs xz  1416 inodes declared
...
157 components, 152 versioned, 5 unversioned
```

0.7 seconds. OpenWrt ships an opkg database, so most of that is read rather than inferred — which is the point: felf uses the best evidence in the image and records which kind it was. Every claim in the SBOM says whether it came from a database, a version string, a build path or a SONAME.

## Findings

**Devices ship duplicate components at different versions**: The R7000 carries OpenSSL 1.0.2h *and* 1.0.2r, curl 7.36.0 *and* 7.61.1, zlib 1.2.5 *and* 1.2.8. An inventory with one entry per component is wrong about this device no matter how good its detection is. Patching the base copy leaves the bundled one exposed.

<p align="center"><img src="assets/duplicates.gif" alt="two versions of openssl, curl and zlib in one device" width="88%"/></p>

---

SBOM records how components identified; version string, build path, SONAME, package filename and which file it came from.

<p align="center"><img src="assets/report.gif" alt="CycloneDX output with evidence" width="88%"/></p>

## Accuracy

Graded against Alpine Linux packages. Package metadata stripped from test tree, so analyzer works from binaries.

| | |
|---|---|
| components present | 50 |
| version claims made | 21 |
| **correct claims** | **21** |
| **precision** | **100%** |
| version recall | 42% |

All version claims correct. 42% recall means most components are identified but not versioned. An unversioned component is reported as present with no version. The ratchet is a test: with the ground-truth corpus mounted, `cargo test --release -- --ignored` fails if any claim is wrong or recall drops below 40%. It is ignored by default because the corpus is too large to ship, and it fails rather than skips when asked for without one.

Those 21 claims are graded against a synthetic Alpine tree. On real firmware the harder question is how much binary evidence recovers on its own, and `reconcile` measures it: of 140 packages an OpenWrt image declares, 4 match a project felf has a rule for — and it corroborated all 4 from the bytes. The limit is the size of the curated project table, not the technique. [docs/PROOF.md](docs/PROOF.md) carries the full split, including the part that is close to circular.

## Build

```
cargo build --release
```

No C dependencies. Single binary, ~3MB. The SquashFS reader is implemented directly, as is the LZMA1 decoder.

## Use

```
felf scan firmware.bin
felf scan firmware.bin --unversioned
felf scan firmware.bin --sbom out.cdx.json --report out.html --baseline 3
felf unpack firmware.bin --out ./rootfs
felf reconcile firmware.bin --manifest build.manifest
```

`reconcile` compares a build manifest — Yocto, Buildroot, OpenWrt, dpkg — against what the image
supports, and separates what the bytes corroborate from what only the image's own package
database does. It reports entries it could not corroborate and components it could not match to
a manifest entry; it does not claim either is missing.

Takes zip, tar, gzip, Netgear CHK, Broadcom TRX, u-boot uImage, or a raw image. You should not have to unwrap anything first.

`--baseline N` is component count from SBOM you already have; the HTML report shows difference.

## Claim

**The output is inventory, not a vulnerability assessment**: It reports which components are
present at which versions. It does not claim any of them to be exploitable in your device.

**Coverage gaps include**: encrypted containers, unsupported formats, regions
that could not be parsed are stated explicitly in both the SBOM and the report. An image
that cannot be opened still produces a document saying so.

**Precision is measured on 21 version claims**, graded against Alpine ground truth containing 50 components. Twenty-one correct out of twenty-one is a real number, not a large one. The corpus in the table above is 7 vendor images out of 11 attempted.

## Detail

| | |
|---|---|
| [docs/PROOF.md](docs/PROOF.md) | every number on this page, and how it was measured |
| [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) | what it does to a file, and why each rule exists |
| [docs/FOR-MANUFACTURERS.md](docs/FOR-MANUFACTURERS.md) | the same thing without the jargon |
| [research/FINDINGS.md](research/FINDINGS.md) | the full evidence trail, including what was tried and retracted |
| [CHANGELOG.md](CHANGELOG.md) | what changed and why |

## Status

v0.0.2. Working, tested, and not yet used by anyone but its author.

## Licence

AGPL-3.0 or later

