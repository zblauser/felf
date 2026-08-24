//! Extraction regression guard. A change that improves one image while silently breaking
//! others is the failure mode this catches — adding uImage support once cost three images
//! because the payload replaced the raw scan instead of supplementing it.
//!
//! Set FELF_CORPUS to the vendor firmware directory to enable.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scan(path: &Path) -> Option<(usize, usize)> {
	let out = Command::new(env!("CARGO_BIN_EXE_felf")).arg("scan").arg(path).output().ok()?;
	let text = String::from_utf8_lossy(&out.stdout);
	let files = text
		.split_whitespace()
		.zip(text.split_whitespace().skip(1))
		.find(|(_, next)| *next == "files")
		.and_then(|(n, _)| n.parse().ok())?;
	let comps = text
		.split_whitespace()
		.zip(text.split_whitespace().skip(1))
		.find(|(_, next)| next.starts_with("components"))
		.and_then(|(n, _)| n.parse().ok())?;
	Some((files, comps))
}

fn find(dir: &Path, fragment: &str) -> Option<PathBuf> {
	std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).find(|p| {
		p.file_name().is_some_and(|n| n.to_string_lossy().contains(fragment))
	})
}

#[test]
fn extracts_known_corpus_images() {
	let Ok(dir) = std::env::var("FELF_CORPUS") else {
		eprintln!("FELF_CORPUS unset; skipping");
		return;
	};
	let dir = PathBuf::from(dir);
	let expected = [
		("netgear-r7000", 1500usize, 40usize),
		("tplink-archer-c7-v5", 2000, 18),
		("asus-rt-ac68u", 2400, 35),
		("dlink-dir-655", 800, 15),
		("dlink-dns-320", 2700, 24),
		("ubiquiti-er-x", 21000, 40),
	];
	let mut failures = Vec::new();
	for (fragment, min_files, min_comps) in expected {
		let Some(path) = find(&dir, fragment) else { continue };
		match scan(&path) {
			Some((files, comps)) if files >= min_files && comps >= min_comps => {}
			other => failures
				.push(format!("{fragment}: got {other:?}, want >= ({min_files}, {min_comps})")),
		}
	}
	assert!(failures.is_empty(), "extraction regressed:\n{}", failures.join("\n"));
}
