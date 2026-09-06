//! What a build system says it shipped, compared against what the bytes support.
//!
//! The comparison is deliberately one-directional. Deciding that a declared package is
//! *absent*, or that a found component is *undeclared*, would need a package-name to
//! upstream-project mapping: 56% of an OpenWrt manifest is `kmod-*`, `luci-*` and `lib*`
//! naming, and `kmod-ath9k - 6.6.73.6.12.6-r1` carries the kernel version rather than a
//! component version. Debian supplies that mapping in its `Source:` field and nothing else
//! does. So a name that fails to match is reported as a name that failed to match.

use std::collections::{BTreeMap, BTreeSet};

use felf_core::Component;

use crate::{normalize_pkg, package_database, refines, upstream_version, VersionStyle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
	/// `Package:` / `Version:` / `Source:` stanzas — dpkg, opkg status.
	Control,
	/// `busybox - 1.36.1-r2`, as emitted next to an OpenWrt image.
	OpenWrt,
	/// Two whitespace-separated columns. Versions are passed through untouched, because
	/// nothing is known about the packaging convention that produced them.
	Generic,
}

impl Format {
	fn version_style(self) -> VersionStyle {
		match self {
			Format::Control => VersionStyle::Control,
			Format::OpenWrt => VersionStyle::Revision,
			Format::Generic => VersionStyle::Verbatim,
		}
	}

	pub fn name(self) -> &'static str {
		match self {
			Format::Control => "debian control",
			Format::OpenWrt => "openwrt manifest",
			Format::Generic => "generic two-column",
		}
	}
}

#[derive(Debug, Clone)]
pub struct Declared {
	/// Normalized for matching.
	pub project: String,
	/// As the manifest wrote it, for display — the two differ often enough to matter.
	pub raw: String,
	pub version: Option<String>,
}

#[derive(Debug)]
pub struct Corroborated {
	pub project: String,
	pub declared: Option<String>,
	pub observed: Vec<String>,
	/// None when either side carries no version, so nothing was compared.
	pub agrees: Option<bool>,
	pub evidence: BTreeSet<&'static str>,
}

impl Corroborated {
	/// Whether anything other than the image's own package database supports this. The
	/// difference between reading a manifest and recovering a component from bytes.
	pub fn from_bytes(&self) -> bool {
		self.evidence.iter().any(|k| *k != "package-database")
	}
}

#[derive(Debug, Default)]
pub struct Reconciliation {
	pub corroborated: Vec<Corroborated>,
	/// Declared, with nothing in the image supporting it. Not a claim of absence.
	pub uncorroborated: Vec<Declared>,
	/// Found in the image, matching no manifest entry by name. A naming question.
	pub unmatched: Vec<String>,
}

impl Reconciliation {
	pub fn disagreements(&self) -> impl Iterator<Item = &Corroborated> {
		self.corroborated.iter().filter(|c| c.agrees == Some(false))
	}
}

pub fn parse(data: &[u8]) -> (Format, Vec<Declared>) {
	let text = String::from_utf8_lossy(data);
	let format = detect(&text);
	let style = format.version_style();
	let entries = match format {
		Format::Control => package_database(data)
			.into_iter()
			.map(|(raw, version)| declared(raw, Some(version)))
			.collect(),
		Format::OpenWrt | Format::Generic => text
			.lines()
			.filter_map(|line| split_columns(line, format))
			.map(|(raw, version)| {
				let version = version.map(|v| upstream_version(v, style));
				declared(raw.to_string(), version)
			})
			.collect(),
	};
	(format, entries)
}

fn declared(raw: String, version: Option<String>) -> Declared {
	Declared { project: normalize_pkg(&raw.to_lowercase()), raw, version }
}

fn detect(text: &str) -> Format {
	if text.lines().any(|l| l.starts_with("Package:")) {
		return Format::Control;
	}
	// ` - ` is the OpenWrt separator and is not a plausible package name character, so one
	// well-formed line is enough to tell the two column formats apart.
	if text.lines().any(|l| l.split(" - ").count() == 2 && !l.starts_with(' ')) {
		return Format::OpenWrt;
	}
	Format::Generic
}

fn split_columns(line: &str, format: Format) -> Option<(&str, Option<&str>)> {
	let line = line.trim();
	if line.is_empty() || line.starts_with('#') {
		return None;
	}
	let (name, version) = match format {
		Format::OpenWrt => line.split_once(" - ")?,
		_ => match line.split_once(char::is_whitespace) {
			Some((n, v)) => (n, v),
			None => (line, ""),
		},
	};
	let version = version.split_whitespace().next().filter(|v| !v.is_empty());
	Some((name, version))
}

pub fn reconcile(declared: &[Declared], observed: &[Component]) -> Reconciliation {
	let mut by_project: BTreeMap<&str, Vec<&Component>> = BTreeMap::new();
	for c in observed {
		by_project.entry(c.project.as_str()).or_default().push(c);
	}

	let mut out = Reconciliation::default();
	let mut matched: BTreeSet<&str> = BTreeSet::new();

	for entry in declared {
		let Some(components) = by_project.get(entry.project.as_str()) else {
			out.uncorroborated.push(entry.clone());
			continue;
		};
		matched.insert(entry.project.as_str());

		let observed_versions: Vec<String> =
			components.iter().filter_map(|c| c.version.clone()).collect();
		let evidence: BTreeSet<&'static str> =
			components.iter().flat_map(|c| c.evidence.iter().map(|e| e.kind.label())).collect();
		let agrees = match (&entry.version, observed_versions.is_empty()) {
			(Some(want), false) => {
				Some(observed_versions.iter().any(|got| refines(want, got)))
			}
			_ => None,
		};
		out.corroborated.push(Corroborated {
			project: entry.project.clone(),
			declared: entry.version.clone(),
			observed: observed_versions,
			agrees,
			evidence,
		});
	}

	for project in by_project.keys() {
		if !matched.contains(project) {
			out.unmatched.push((*project).to_string());
		}
	}
	out
}
