//! Build-path mining is the highest-yield version signal and the easiest to get wrong:
//! a toolchain directory is not the component it was built for.

use felf_core::store::Store;
use felf_identify::Analyzer;

/// Build paths are compiler artifacts, so fixtures must look like objects rather than
/// text — the analyzer deliberately ignores paths quoted inside text files.
fn as_binary(blob: &[u8]) -> Vec<u8> {
	let mut out = b"\x7fELF\x02\x01\x01\x00".to_vec();
	out.extend_from_slice(&[0u8; 64]);
	out.extend_from_slice(blob);
	out.extend((0..256u32).map(|i| (i.wrapping_mul(37) % 251) as u8));
	out
}

fn analyze(path: &str, blob: &[u8]) -> Vec<(String, Option<String>)> {
	let mut store = Store::new();
	store.insert(path, as_binary(blob));
	Analyzer::new()
		.analyze(&store)
		.into_iter()
		.map(|c| (c.project, c.version))
		.collect()
}

#[test]
fn toolchain_directory_is_not_a_component_version() {
	// 4.5.3 is the GCC in Broadcom's toolchain, not a uClibc release.
	let blob = b"/projects/hnd/tools/linux/hndtools-arm-linux-2.6.36-uclibc-4.5.3/lib";
	let found = analyze("usr/sbin/daemon", blob);
	assert!(
		!found.iter().any(|(p, v)| p == "uclibc" && v.as_deref() == Some("4.5.3")),
		"toolchain path mistaken for a component version: {found:?}"
	);
}

#[test]
fn gcc_output_directory_is_ignored() {
	let found = analyze("usr/sbin/tool", b"/output/toolchain/gcc-4.5.3/bin");
	assert!(!found.iter().any(|(p, _)| p == "gcc-runtime" || p == "gcc"), "{found:?}");
}

#[test]
fn hyphenated_crate_names_survive_intact() {
	let blob = b"/root/.cargo/registry/src/github.com-1ecc6299db9ec823/num-integer-0.1.42/src";
	let found = analyze("bin/agent", blob);
	assert!(
		found.iter().any(|(p, v)| p == "rust:num-integer" && v.as_deref() == Some("0.1.42")),
		"crate name truncated: {found:?}"
	);
}

#[test]
fn cargo_crates_do_not_borrow_c_project_identities() {
	let blob = b"/root/.cargo/registry/src/github.com-1ecc6299db9ec823/curl-0.4.25/src";
	let found = analyze("bin/agent", blob);
	assert!(found.iter().any(|(p, _)| p == "rust:curl"), "{found:?}");
	assert!(
		!found.iter().any(|(p, v)| p == "curl" && v.as_deref() == Some("0.4.25")),
		"rust crate reported as the C library: {found:?}"
	);
}

#[test]
fn plain_source_directory_still_yields_a_version() {
	let found = analyze("bin/ipset", b"/home/dev/build/ipset-6.29/src/ipset.c");
	assert!(
		found.iter().any(|(p, v)| p == "ipset" && v.as_deref() == Some("6.29")),
		"build-path mining stopped working: {found:?}"
	);
}

#[test]
fn paths_quoted_in_text_files_are_not_build_evidence() {
	// Real case: usr/share/perl/5.24.1/.../Perl.pm mentions /perl-5.6/ in its source.
	// The containing path says 5.24.1; the mention is content, not provenance.
	let blob = b"package TAP::Parser;\n# historic layouts used /perl-5.6/lib\nsub run { 1 }\n";
	let mut store = Store::new();
	store.insert("usr/share/perl/5.24.1/TAP/Parser/SourceHandler/Perl.pm", blob.to_vec());
	let found: Vec<(String, Option<String>)> = Analyzer::new()
		.analyze(&store)
		.into_iter()
		.map(|c| (c.project, c.version))
		.collect();
	assert!(
		!found.iter().any(|(p, v)| p == "perl" && v.as_deref() == Some("5.6")),
		"quoted path in a text file treated as a build path: {found:?}"
	);
}
