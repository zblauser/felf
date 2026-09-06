//! End-to-end reconcile against a real OpenWrt image and the manifest published beside it.
//!
//! Ignored by default: the image is 6.6MB and not shippable. Run with
//! `FELF_OPENWRT=<dir holding the .bin and .manifest> cargo test --release -- --ignored`.
//! Asked for without the directory it fails rather than skipping — a gate that reports a
//! pass without running is worse than no gate.

use std::path::{Path, PathBuf};
use std::process::Command;

fn find(dir: &Path, fragment: &str, ext: &str) -> Option<PathBuf> {
	std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).find(|p| {
		let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
		name.contains(fragment) && name.ends_with(ext)
	})
}

fn count_after(text: &str, label: &str) -> Option<usize> {
	let line = text.lines().find(|l| l.trim_start().starts_with(label))?;
	line.split_whitespace().find_map(|w| w.parse().ok())
}

#[test]
#[ignore = "requires FELF_OPENWRT; run with --ignored"]
fn reconciles_an_openwrt_image_against_its_manifest() {
	let dir = match std::env::var("FELF_OPENWRT") {
		Ok(dir) => PathBuf::from(dir),
		Err(_) => panic!("FELF_OPENWRT unset; point it at the directory holding the OpenWrt images"),
	};
	assert!(dir.is_dir(), "FELF_OPENWRT={} is not a directory", dir.display());

	let image = find(&dir, "ath79", ".bin").expect("no ath79 .bin in FELF_OPENWRT");
	let manifest = find(&dir, "ath79", ".manifest").expect("no ath79 .manifest in FELF_OPENWRT");

	let out = Command::new(env!("CARGO_BIN_EXE_felf"))
		.arg("reconcile")
		.arg(&image)
		.arg("--manifest")
		.arg(&manifest)
		.output()
		.expect("run felf reconcile");
	let text = String::from_utf8_lossy(&out.stdout);
	assert!(out.status.success(), "reconcile failed: {}", String::from_utf8_lossy(&out.stderr));

	let corroborated = count_after(&text, "corroborated").expect("corroborated line");
	let from_bytes = count_after(&text, "from the bytes").expect("from the bytes line");

	// The manifest and the image's opkg database come from one build, so nearly everything
	// corroborates. The figure that means anything is how much the bytes independently
	// support, and it is small — that is the honest state of version recovery on real
	// firmware, not a bug to be tuned away.
	assert!(corroborated >= 120, "corroborated collapsed to {corroborated}:\n{text}");
	assert!(from_bytes >= 1, "no component corroborated from bytes at all:\n{text}");
	assert!(
		!text.contains("undeclared"),
		"reconcile must not assert absence or undeclared components:\n{text}"
	);
}
