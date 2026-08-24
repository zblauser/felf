//! Two versions for one project mean different things depending on where they came from.

use felf_core::store::Store;
use felf_identify::Analyzer;

fn as_binary(blob: &[u8]) -> Vec<u8> {
	let mut out = b"\x7fELF\x02\x01\x01\x00".to_vec();
	out.extend_from_slice(&[0u8; 64]);
	out.extend_from_slice(blob);
	out.extend((0..256u32).map(|i| (i.wrapping_mul(37) % 251) as u8));
	out
}

fn analyze(files: &[(&str, &[u8])]) -> Vec<(String, Option<String>)> {
	let mut store = Store::new();
	for (path, blob) in files {
		store.insert(*path, as_binary(blob));
	}
	Analyzer::new()
		.analyze(&store)
		.into_iter()
		.map(|c| (c.project, c.version))
		.collect()
}

#[test]
fn two_versions_in_separate_files_are_two_components() {
	// A device really can ship two generations of one library, and patching one leaves
	// the other exposed.
	let found = analyze(&[
		("lib/libcrypto.so.1.0.0", b"OpenSSL 1.0.2h  3 May 2016"),
		("opt/vendor/libcrypto.so.1.0.0", b"OpenSSL 1.0.2r  26 Feb 2019"),
	]);
	let versions: Vec<_> = found
		.iter()
		.filter(|(p, _)| p == "openssl")
		.filter_map(|(_, v)| v.clone())
		.collect();
	assert!(versions.contains(&"1.0.2h".to_string()), "{found:?}");
	assert!(versions.contains(&"1.0.2r".to_string()), "{found:?}");
}

#[test]
fn two_versions_in_one_file_yield_no_version() {
	// sshd carries a compatibility table of old releases; nothing in the bytes says which
	// string is the binary's own version.
	let found = analyze(&[("usr/sbin/sshd", b"OpenSSH_7.4p1 xx OpenSSH_2.1 compat")]);
	let openssh: Vec<_> = found.iter().filter(|(p, _)| p == "openssh").collect();
	assert!(!openssh.is_empty(), "openssh should still be reported as present");
	assert!(
		openssh.iter().all(|(_, v)| v.is_none()),
		"contradictory evidence should not produce a version: {found:?}"
	);
}

#[test]
fn a_refinement_is_not_a_contradiction() {
	// A build path often carries the release series while the binary carries the point
	// release. Only the specific one should survive.
	let found = analyze(&[(
		"usr/lib/libcrypto.so.1.0.2",
		b"/build/openssl-1.0.2/crypto\x00OpenSSL 1.0.2u  20 Dec 2019",
	)]);
	let versions: Vec<_> = found
		.iter()
		.filter(|(p, _)| p == "openssl")
		.filter_map(|(_, v)| v.clone())
		.collect();
	assert_eq!(versions, vec!["1.0.2u".to_string()], "{found:?}");
}
