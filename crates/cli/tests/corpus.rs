//! Extraction regression guard. A change that improves one image while silently breaking
//! others is the failure mode this catches — adding uImage support once cost three images
//! because the payload replaced the raw scan instead of supplementing it.
//!
//! Ignored by default: the corpus is vendor firmware, too large to ship. Run the gate with
//! `FELF_CORPUS=<vendor firmware dir> cargo test --release -- --ignored`. An image the
//! corpus is missing counts as a failure, not a skip — otherwise an empty directory
//! reports a pass.

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
#[ignore = "requires FELF_CORPUS; run with --ignored"]
fn extracts_known_corpus_images() {
	let dir = match std::env::var("FELF_CORPUS") {
		Ok(dir) => PathBuf::from(dir),
		Err(_) => panic!("FELF_CORPUS unset; point it at the vendor firmware directory"),
	};
	assert!(dir.is_dir(), "FELF_CORPUS={} is not a directory", dir.display());
	let expected = [
		("netgear-r7000", 1500usize, 40usize),
		("tplink-archer-c7-v5", 2000, 18),
		("asus-rt-ac68u", 2400, 35),
		("dlink-dir-655", 800, 15),
		("dlink-dns-320", 2700, 20),
		("ubiquiti-er-x", 21000, 35),
	];
	let mut failures = Vec::new();
	for (fragment, min_files, min_comps) in expected {
		let Some(path) = find(&dir, fragment) else {
			failures.push(format!("{fragment}: no image matching this name in {}", dir.display()));
			continue;
		};
		match scan(&path) {
			Some((files, comps)) if files >= min_files && comps >= min_comps => {}
			other => failures
				.push(format!("{fragment}: got {other:?}, want >= ({min_files}, {min_comps})")),
		}
	}
	assert!(failures.is_empty(), "extraction regressed:\n{}", failures.join("\n"));
}
