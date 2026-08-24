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
| Ubiquiti EdgeRouter X | router (Debian) | 21803 | 37 | 10 | **838** |

The DIR-655 is the obvious case: standard toolchain produces entirely empty document for a shipping consumer router.

The EdgeRouter is the honest counter example. It carries a real Debian package database, existing tooling already works well there, and felf adds little. This is currently a tool for firmware **without** a usable package database; which is most current consumer and embedded devices.

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

All version claims correct. 42% recall means most components are identified but not versioned. An unversioned component is reported as present with no version. `cargo test` fails the build if precision regresses.

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
```

Takes zip, tar, gzip, Netgear CHK, Broadcom TRX, u-boot uImage, or a raw image. You should not have to unwrap anything first.

`--baseline N` is component count from SBOM you already have; the HTML report shows difference.

## Claim

**The output is inventory, not a vulnerability assessment**: It reports which components are
present at which versions. It does not claim any of them to be exploitable in your device.

**Coverage gaps include**: encrypted containers, unsupported formats, regions
that could not be parsed are stated explicitly in both the SBOM and the report. An image
that cannot be opened still produces a document saying so.

**Precision only measured on 21 assorted firmware currently.**

## Status

v0.0.1. Working, tested, and not yet used by anyone but its author.

## Licence

AGPL-3.0 or later

