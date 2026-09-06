# What felf is for

*Written for whoever has to sign the paperwork. No prior knowledge assumed.*

---

## The short version

If your company sells a product with software inside it, you are about to be legally
required to publish a list of what that software is made of. You probably cannot produce
that list accurately today, because you did not write most of it and cannot see inside the
parts your suppliers gave you.

felf reads your firmware and tells you what is actually in there.

---

## 1. Your product contains hundreds of things you did not write

Every connected device — a router, a camera, a thermostat, a monitor, an industrial sensor —
runs software. That software is not written from scratch. It is assembled from free,
open-source building blocks: something that handles encryption, something that compresses
files, something that runs a small web server, a version of Linux underneath it all.

A typical device contains between one hundred and four hundred of these.

Some came from your engineers. Many arrived inside a chip vendor's development kit. Some
were added by a contract manufacturer. On one router we examined, **21MB of a 30MB image —
roughly seventy percent of the product — was a single bundled package from a third-party
security company.** The company selling the router did not build it and had no practical
way to see inside it.

## 2. Those pieces develop security flaws, constantly

When a flaw is found in one of these building blocks, every product containing it becomes
vulnerable at once. The blocks are shared across the whole industry, so a single flaw can
affect millions of devices from hundreds of manufacturers.

The obvious question — *"is that thing in our product?"* — is one most manufacturers cannot
answer quickly, because nobody ever wrote down what went in.

## 3. So regulators are now requiring the list

The list is called an **SBOM**, a Software Bill of Materials. Think of it as the ingredients
label on food packaging.

**Europe — the Cyber Resilience Act.** From **11 December 2027**, you cannot legally sell a
product with digital elements into the EU without one, along with a process for handling
flaws found in it. Penalties reach €15 million or 2.5% of worldwide turnover. This applies
to American and Asian companies exactly as it applies to European ones — if your product
reaches an EU customer, the law reaches you. Earlier obligations around reporting actively
exploited vulnerabilities began on 11 September 2026.

**United States — FDA.** Medical devices already require an SBOM in the premarket
submission. No list, no clearance, no product.

In both cases **a named person signs a declaration that the information is accurate.**

## 4. The tools everyone uses were built for different software

The standard way to produce this list works well for web and cloud software, because that
kind of software declares its own ingredients in a file the tool can read.

Firmware does not work that way:

- It is written in C and C++, where borrowed code is **compiled directly into the program**.
  The seams disappear. There is no list to read.
- It usually has **no package database** — nothing on the device records what was installed.
- Large parts of it are frequently **sealed inside a nested archive** the tool never opens.
- Some vendor images are in formats standard tools **cannot open at all**.

The result is not an error message. It is a clean-looking document that is wrong.

## 5. How wrong

We ran the standard toolchain and felf over the same firmware images, downloaded from the
manufacturers' own websites.

| device | standard toolchain | felf |
|---|---|---|
| Netgear R7000 router | 3 components | **61** |
| ASUS RT-AC68U router | 5 components | **41** |
| D-Link DNS-320 storage | 2 components | **22** |
| TP-Link Archer C7 router | 4 components | **22** |
| **D-Link DIR-655 router** | **0 components** | **19** |

On the DIR-655, the standard toolchain produces a **completely empty document** for a
shipping consumer router. It is not that the tool failed loudly — it produced a file with
nothing in it.

We also found devices carrying **two different versions of the same component at once**.
The Netgear router ships two OpenSSL versions, two curl versions and two zlib versions. Fix
the one you know about and the other is still there.

## 6. What felf actually does

You give it the firmware file — the same file you publish as a download, or the output of
your build. It:

- opens the image, including formats other tools cannot
- looks inside nested archives rather than treating them as one lump
- identifies which open-source components are present and, where it can determine it, at
  which version
- records **why** it believes each thing, so any claim can be checked
- writes a standards-compliant SBOM (CycloneDX) and a readable report
- **states plainly what it could not read**

It never touches a running device and needs no network access.

## 7. What it will not do, and why that matters

**It will not tell you that you are safe.** It is an inventory, not a security assessment.
It reports what is present. Whether a given flaw is actually exploitable in your device is a
separate question requiring separate work.

**It will not always determine a version.** Roughly six components in ten are identified but
not versioned, because the information simply is not present in the binary. In those cases
felf says so rather than guessing.

That last point is the design decision the whole tool rests on. **Every version it does
report has been correct in testing — 21 out of 21 against a controlled reference set.** It
would be easy to raise the numbers by guessing. But you are signing a legal declaration: a
gap you can point to is a manageable problem, and a confident wrong answer is a false
statement with your name on it.

**Some images cannot be opened by anyone.** Encrypted firmware needs the vendor's key. When
felf meets one it produces a document saying exactly that — which is the artifact you file,
and which maps onto the regulation's own answer: obtain the SBOM from your supplier
contractually.

## 8. What this is worth to you

- **You can answer the question.** When the next widely-publicised flaw lands, you know
  within minutes whether it is in your products.
- **The declaration you sign is defensible.** Every entry has evidence attached, and the
  gaps are documented rather than hidden.
- **You find out what your suppliers actually shipped you** — including the parts you did
  not build and cannot otherwise inspect.
- **It runs in your build pipeline**, offline, on every release, rather than being a
  consulting engagement repeated annually.

---

## Current status

felf is new. It works, it is tested, and its accuracy is measured and published rather than
asserted. It has not yet been used in anger by anyone other than its author, and it is
honest about that.

If you make connected hardware and have to answer to the Cyber Resilience Act or the FDA,
we would like to run it against your firmware and show you what comes back.
