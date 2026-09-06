use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use felf_core::bytes::find as find_bytes;
use felf_core::{store::Store, Component, Confidence, Evidence, EvidenceKind};
use regex::bytes::Regex as ByteRegex;
use regex::Regex;

pub mod manifest;
pub mod rules;

pub struct Analyzer {
	filename: Vec<(Regex, &'static str)>,
	version: Vec<(&'static str, Vec<ByteRegex>)>,
	soname_release: Vec<(&'static str, Regex)>,
	filename_version: Vec<(&'static str, Regex)>,
	build_path: ByteRegex,
	package_file: Regex,
}

#[derive(Default)]
struct Found {
	/// version -> the files that yielded it. Two versions from *different* files is a
	/// device shipping two copies (R7000 carries openssl 1.0.2h and 1.0.2r). Two versions
	/// from the *same* file is contradictory evidence about one artifact.
	versions: BTreeMap<String, BTreeSet<PathBuf>>,
	evidence: Vec<Evidence>,
}

impl Found {
	fn record(&mut self, version: String, path: &Path) {
		self.versions.entry(version).or_default().insert(path.to_path_buf());
	}

	/// A file that yields more than one version for the same project is not evidence of
	/// two components. sshd carries a compatibility table of old OpenSSH releases, so
	/// `usr/sbin/sshd` produces both 7.4 and 2.1 — one is the binary, one is a lookup
	/// string, and nothing in the bytes says which.
	fn contradictory(&self) -> bool {
		let mut per_file: BTreeMap<&PathBuf, Vec<&String>> = BTreeMap::new();
		for (version, paths) in &self.versions {
			for p in paths {
				per_file.entry(p).or_default().push(version);
			}
		}
		per_file
			.values()
			.any(|vs| vs.iter().any(|a| vs.iter().any(|b| !refines(a, b))))
	}

	/// Collapse `1.0.2` into `1.0.2u` — a build path often carries the release series while
	/// the binary carries the point release. Only the specific one is reported.
	fn collapse_refinements(&mut self) {
		let all: Vec<String> = self.versions.keys().cloned().collect();
		for v in &all {
			if all.iter().any(|other| other != v && other.starts_with(v.as_str())) {
				self.versions.remove(v);
			}
		}
	}
}

impl Default for Analyzer {
	fn default() -> Self {
		Self::new()
	}
}

impl Analyzer {
	pub fn new() -> Self {
		Self {
			filename: rules::FILENAME
				.iter()
				.filter_map(|(p, proj)| Regex::new(p).ok().map(|r| (r, *proj)))
				.collect(),
			version: rules::VERSION
				.iter()
				.map(|(proj, pats)| {
					(*proj, pats.iter().filter_map(|p| ByteRegex::new(p).ok()).collect())
				})
				.collect(),
			soname_release: rules::SONAME_RELEASE
				.iter()
				.filter_map(|(proj, p)| Regex::new(p).ok().map(|r| (*proj, r)))
				.collect(),
			filename_version: rules::FILENAME_VERSION
				.iter()
				.filter_map(|(proj, p)| Regex::new(p).ok().map(|r| (*proj, r)))
				.collect(),
			// The name must absorb hyphens. Excluding them truncated `num-integer-0.1.42`
			// to `integer`, and let the Broadcom toolchain directory
			// `hndtools-arm-linux-2.6.36-uclibc-4.5.3` masquerade as uClibc 4.5.3 —
			// that version is the bundled GCC, not the libc.
			build_path: ByteRegex::new(
				r"[/\\]([A-Za-z][A-Za-z0-9_.+-]{1,40}?)[-_](\d+\.\d+(?:\.\d+)?[a-z]?)[/\\]",
			)
			.expect("build path pattern"),
			package_file: Regex::new(r"^(?:asus)?([A-Za-z][\w.+-]*?)[-_](\d[\w.]*?)(?:-\d+)?_\w+\.(?:ipk|deb)$")
				.expect("package filename pattern"),
		}
	}

	fn classify(&self, name: &str) -> Option<&'static str> {
		if let Some((_, proj)) = self.filename.iter().find(|(re, _)| re.is_match(name)) {
			return Some(proj);
		}
		rules::BINARY.iter().find(|(b, _)| *b == name).map(|(_, proj)| *proj)
	}

	/// libc.so alone is ambiguous; the bytes are not.
	fn disambiguate_libc(data: &[u8]) -> Option<&'static str> {
		rules::LIBC_MARKER
			.iter()
			.find(|(marker, _)| find_bytes(data, marker.as_bytes()).is_some())
			.map(|(_, proj)| *proj)
	}

	pub fn analyze(&self, store: &Store) -> Vec<Component> {
		let mut found: BTreeMap<String, Found> = BTreeMap::new();
		let mut paths: Vec<_> = store.paths().collect();
		paths.sort();

		for path in paths {
			let Some(data) = store.get(path) else { continue };
			let name = match path.file_name().and_then(|n| n.to_str()) {
				Some(n) => n,
				None => continue,
			};

			if is_package_database(path) {
				for (pkg, version) in package_database(data) {
					let entry = found.entry(normalize_pkg(&pkg)).or_default();
					let value = format!("{pkg} {version}");
					entry.evidence.push(ev(EvidenceKind::PackageDatabase, path, &value, Confidence::Confirmed));
					entry.record(version, path);
				}
				continue;
			}

			if let Some(caps) = self.package_file.captures(name) {
				let entry = found.entry(normalize_pkg(&caps[1])).or_default();
				entry.record(caps[2].to_string(), path);
				entry.evidence.push(ev(EvidenceKind::PackageFilename, path, name, Confidence::Confirmed));
				continue;
			}

			if !is_text(data) {
				self.mine_build_paths(data, path, &mut found);
			}

			let Some(mut proj) = self.classify(name) else { continue };
			if matches!(proj, "uclibc" | "musl" | "glibc") || name.starts_with("libc.so") {
				if let Some(actual) = Self::disambiguate_libc(data) {
					proj = actual;
				}
			}

			let entry = found.entry(proj.to_string()).or_default();
			entry.evidence.push(ev(EvidenceKind::Soname, path, name, Confidence::Likely));

			for (p, re) in &self.soname_release {
				if *p == proj {
					if let Some(c) = re.captures(name) {
						entry.record(c[1].to_string(), path);
						entry.evidence.push(ev(EvidenceKind::Soname, path, &c[1], Confidence::Confirmed));
					}
				}
			}
			for (p, re) in &self.filename_version {
				if *p == proj {
					if let Some(c) = re.captures(name) {
						entry.record(c[1].to_string(), path);
						entry.evidence.push(ev(EvidenceKind::PackageFilename, path, &c[1], Confidence::Confirmed));
					}
				}
			}
			if let Some((_, pats)) = self.version.iter().find(|(p, _)| *p == proj) {
				let data = &data[..data.len().min(16 << 20)];
				for re in pats {
					for c in re.captures_iter(data) {
						if let Some(m) = c.get(1) {
							let v = String::from_utf8_lossy(m.as_bytes()).into_owned();
							entry.evidence.push(ev(EvidenceKind::VersionString, path, &v, Confidence::Confirmed));
							entry.record(v, path);
						}
					}
				}
			}
		}

		build_components(found)
	}

	/// Compilers embed __FILE__ and debug paths; vendors rarely strip them, so a source
	/// directory name often carries a version no string table exposes.
	fn mine_build_paths(&self, data: &[u8], path: &Path, found: &mut BTreeMap<String, Found>) {
		const SKIP: &[&str] = &["linux", "gcc", "glibc", "build", "tmp", "usr", "home", "opt", "work", "src", "lib", "obj"];
		for c in self.build_path.captures_iter(data) {
			let (Some(whole), Some(n), Some(v)) = (c.get(0), c.get(1), c.get(2)) else { continue };
			let name = String::from_utf8_lossy(n.as_bytes()).to_lowercase();
			if name.len() < 3 || SKIP.contains(&name.as_str()) {
				continue;
			}
			let ver = String::from_utf8_lossy(v.as_bytes()).into_owned();

			// A cargo registry path names a Rust crate, not the C project it may share a
			// name with. `curl 0.4.25` is the crate; mapping it to haxx:curl invents CVEs.
			let context = &data[whole.start().saturating_sub(64)..whole.start()];
			if find_bytes(context, b"registry/src").is_some() || find_bytes(context, b".cargo").is_some() {
				let entry = found.entry(format!("rust:{name}")).or_default();
				entry.evidence.push(ev(EvidenceKind::BuildPath, path, &ver, Confidence::Likely));
				entry.record(ver, path);
				continue;
			}

			let Some(proj) = known_project(&name) else { continue };
			let entry = found.entry(proj.to_string()).or_default();
			entry.evidence.push(ev(EvidenceKind::BuildPath, path, &ver, Confidence::Likely));
			entry.record(ver, path);
		}
	}
}

/// A build path embedded by a compiler lives in a binary. A path appearing in a source or
/// documentation file is quoted content — `usr/share/perl/5.24.1/.../Perl.pm` mentions
/// `/perl-5.6/` and is not evidence that perl 5.6 is installed.
fn is_text(data: &[u8]) -> bool {
	let sample = &data[..data.len().min(8192)];
	if sample.is_empty() {
		return false;
	}
	let printable = sample
		.iter()
		.filter(|b| matches!(b, 0x20..=0x7e | b'\n' | b'\r' | b'\t'))
		.count();
	printable * 100 / sample.len() > 95
}

/// One version refines the other when it is the same release expressed more precisely.
pub(crate) fn refines(a: &str, b: &str) -> bool {
	a == b || a.starts_with(b) || b.starts_with(a)
}

fn build_components(found: BTreeMap<String, Found>) -> Vec<Component> {
	let mut out = Vec::new();
	for (project, mut f) in found {
		f.collapse_refinements();
		let f = f;
		let crate_name = project.strip_prefix("rust:");
		let cpes = |v: &str| {
			if crate_name.is_some() {
				return Vec::new();
			}
			rules::CPE
				.iter()
				.find(|(p, _)| *p == project.as_str())
				.map(|(_, bases)| bases.iter().map(|b| cpe_for(b, v)).collect::<Vec<_>>())
				.unwrap_or_default()
		};
		if f.versions.is_empty() || f.contradictory() {
			out.push(Component {
				project: project.clone(),
				version: None,
				cpes: Vec::new(),
				purl: None,
				confidence: Confidence::Possible,
				evidence: f.evidence,
			});
			continue;
		}
		// One entry per version: devices ship duplicate components at different versions
		// (R7000 carries openssl 1.0.2h and 1.0.2r), and patching one leaves the other.
		let multi = f.versions.len() > 1;
		// A path that yielded no surviving version — a bare SONAME, or one whose version
		// was collapsed into a refinement — is a fact about the project rather than about
		// either copy, so it stays on both. Anything else belongs only to the version its
		// own file produced; without this the 1.0.2r entry cites 1.0.2h's bytes.
		let attributed: BTreeSet<&PathBuf> = f.versions.values().flatten().collect();
		for (v, paths) in &f.versions {
			out.push(Component {
				project: project.clone(),
				version: Some(v.clone()),
				cpes: cpes(v),
				purl: Some(match crate_name {
					Some(name) => format!("pkg:cargo/{name}@{v}"),
					None => format!("pkg:generic/{project}@{v}"),
				}),
				confidence: if multi { Confidence::Likely } else { Confidence::Confirmed },
				evidence: f
					.evidence
					.iter()
					.filter(|e| paths.contains(&e.path) || !attributed.contains(&e.path))
					.cloned()
					.collect(),
			});
		}
	}
	out
}

fn cpe_for(base: &str, version: &str) -> String {
	let (vendor, product) = base.split_once(':').unwrap_or((base, base));
	format!("cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*")
}

fn ev(kind: EvidenceKind, path: &Path, value: &str, confidence: Confidence) -> Evidence {
	Evidence { kind, path: path.to_path_buf(), offset: None, value: value.to_string(), confidence }
}

fn known_project(name: &str) -> Option<&'static str> {
	rules::CPE.iter().find(|(p, _)| *p == name).map(|(p, _)| *p)
}

/// opkg and dpkg keep the device's own record of what was installed. Where it exists it is
/// better evidence than anything inferred from bytes — and most firmware has none, which is
/// the reason the rest of this file exists.
fn is_package_database(path: &Path) -> bool {
	path.ends_with("usr/lib/opkg/status") || path.ends_with("var/lib/dpkg/status")
}

/// Both write Debian control stanzas. Continuation lines can contain colons, so only the
/// three fields that matter are matched and everything else is ignored.
pub(crate) fn package_database(data: &[u8]) -> Vec<(String, String)> {
	let text = String::from_utf8_lossy(data);
	let mut out = Vec::new();
	for stanza in text.split("\n\n") {
		let (mut pkg, mut source, mut version, mut installed) = (None, None, None, true);
		for line in stanza.lines() {
			let Some((key, value)) = line.split_once(':') else { continue };
			match key.trim() {
				"Package" => pkg = Some(value.trim().to_lowercase()),
				// Debian binary packages name their upstream project here when the two
				// differ: zlib1g declares Source: zlib. Taking the database's own word
				// beats a curated alias table, which is where invented versions come from.
				"Source" => {
					let raw = value.split('(').next().unwrap_or_default();
					source = Some(raw.trim().to_lowercase());
				}
				"Version" => version = Some(value.trim()),
				// dpkg keeps entries for packages that were removed but left config behind.
				"Status" => installed = value.contains("installed"),
				_ => {}
			}
		}
		let name = source.filter(|s| !s.is_empty()).or(pkg);
		if let (Some(name), Some(version), true) = (name, version, installed) {
			if !name.is_empty() {
				out.push((name, upstream_version(version, VersionStyle::Control)));
			}
		}
	}
	out
}

/// A Debian version is `[epoch:]upstream[-revision]`, and opkg follows the same shape with
/// an `-rN` revision. Only the upstream part is a claim about the upstream project: leaving
/// `1.2.8.dfsg-5` on zlib both overstates what is known and stops the database version
/// matching the `1.2.8` read out of the binary, which would report one library twice.
/// How much of a version string is packaging rather than upstream release. Control files
/// follow Debian's `[epoch:]upstream[-revision]` and the whole trailing field is packaging.
/// A build manifest of unknown provenance does not, and stripping there would turn
/// `1.0.2-beta1` into a claim about `1.0.2`, which shipped different code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionStyle {
	Control,
	/// Strip only an explicit `-rN` package revision.
	Revision,
	Verbatim,
}

pub(crate) fn upstream_version(raw: &str, style: VersionStyle) -> String {
	if style == VersionStyle::Verbatim {
		return raw.to_string();
	}
	let v = match raw.split_once(':') {
		Some((epoch, rest)) if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) => rest,
		_ => raw,
	};
	let v = match (style, v.rsplit_once('-')) {
		(VersionStyle::Control, Some((base, rev))) if !base.is_empty() && !rev.is_empty() => base,
		(VersionStyle::Revision, Some((base, rev)))
			if !base.is_empty()
				&& rev.starts_with('r')
				&& rev.len() > 1
				&& rev[1..].chars().all(|c| c.is_ascii_digit()) =>
		{
			base
		}
		_ => v,
	};
	// `.dfsg` and `+dfsg` mark a tarball Debian repacked to drop non-free files. The code
	// is the upstream release; the suffix describes the packaging.
	for marker in [".dfsg", "+dfsg", "~dfsg", ".orig"] {
		if let Some((base, _)) = v.split_once(marker) {
			return base.to_string();
		}
	}
	v.to_string()
}

pub(crate) fn normalize_pkg(raw: &str) -> String {
	let lower = raw.to_lowercase();
	match lower.as_str() {
		"asuslibcurl" | "libcurl" => "curl".into(),
		"asuslighttpd" => "lighttpd".into(),
		"wxbase" => "wxwidgets".into(),
		other => other.into(),
	}
}

