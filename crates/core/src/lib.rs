use std::fmt;
use std::path::PathBuf;

pub mod bytes;
pub mod store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
	Possible,
	Likely,
	Confirmed,
}

impl fmt::Display for Confidence {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let s = match self {
			Confidence::Possible => "possible",
			Confidence::Likely => "likely",
			Confidence::Confirmed => "confirmed",
		};
		f.write_str(s)
	}
}

impl EvidenceKind {
	pub fn label(&self) -> &'static str {
		match self {
			EvidenceKind::PackageDatabase => "package-database",
			EvidenceKind::PackageFilename => "package-filename",
			EvidenceKind::VersionString => "version-string",
			EvidenceKind::BuildPath => "build-path",
			EvidenceKind::Soname => "soname",
			EvidenceKind::ElfComment => "elf-comment",
			EvidenceKind::ContentMarker => "content-marker",
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceKind {
	PackageDatabase,
	PackageFilename,
	VersionString,
	BuildPath,
	Soname,
	ElfComment,
	ContentMarker,
}

#[derive(Debug, Clone)]
pub struct Evidence {
	pub kind: EvidenceKind,
	pub path: PathBuf,
	pub offset: Option<u64>,
	pub value: String,
	pub confidence: Confidence,
}

#[derive(Debug, Clone)]
pub struct Component {
	pub project: String,
	pub version: Option<String>,
	pub cpes: Vec<String>,
	pub purl: Option<String>,
	pub confidence: Confidence,
	pub evidence: Vec<Evidence>,
}

impl Component {
	pub fn is_versioned(&self) -> bool {
		self.version.is_some()
	}
}

/// A region we could not parse. Emitted rather than skipped: an SBOM that silently omits
/// an encrypted partition is worse than one that declares it.
#[derive(Debug, Clone)]
pub struct CoverageGap {
	pub path: PathBuf,
	pub offset: Option<u64>,
	pub length: Option<u64>,
	pub reason: String,
}

#[derive(Debug, Default)]
pub struct Inventory {
	pub components: Vec<Component>,
	pub gaps: Vec<CoverageGap>,
}

impl Inventory {
	pub fn versioned(&self) -> usize {
		self.components.iter().filter(|c| c.is_versioned()).count()
	}

	pub fn gap(&mut self, path: impl Into<PathBuf>, reason: impl Into<String>) {
		self.gaps.push(CoverageGap {
			path: path.into(),
			offset: None,
			length: None,
			reason: reason.into(),
		});
	}
}

pub fn hash(bytes: &[u8]) -> String {
	blake3::hash(bytes).to_hex().to_string()
}
