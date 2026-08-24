use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Content-addressed view of an extracted tree. Keyed by BLAKE3 so identical payloads
/// appearing at several paths (vendor firmware duplicates constantly) are stored once.
#[derive(Debug, Default)]
pub struct Store {
	blobs: HashMap<String, Vec<u8>>,
	paths: HashMap<PathBuf, String>,
}

impl Store {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn insert(&mut self, path: impl Into<PathBuf>, bytes: Vec<u8>) -> String {
		let digest = crate::hash(&bytes);
		self.paths.insert(path.into(), digest.clone());
		self.blobs.entry(digest.clone()).or_insert(bytes);
		digest
	}

	pub fn get(&self, path: &Path) -> Option<&[u8]> {
		self.paths
			.get(path)
			.and_then(|d| self.blobs.get(d))
			.map(|v| v.as_slice())
	}


	pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
		self.paths.keys()
	}

	pub fn len(&self) -> usize {
		self.paths.len()
	}

	pub fn is_empty(&self) -> bool {
		self.paths.is_empty()
	}

	pub fn unique_blobs(&self) -> usize {
		self.blobs.len()
	}
}
