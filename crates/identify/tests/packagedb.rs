//! opkg and dpkg record what the device believes it installed. Where that file exists it is
//! the best evidence available, and most firmware does not have one — the OpenWrt Archer C7
//! image went from 3 versioned components to 152 on the strength of a single file.

use felf_core::{store::Store, Component};
use felf_identify::Analyzer;

fn components(files: &[(&str, &[u8])]) -> Vec<Component> {
	let mut store = Store::new();
	for (path, blob) in files {
		store.insert(*path, blob.to_vec());
	}
	Analyzer::new().analyze(&store)
}

fn version_of(found: &[Component], project: &str) -> Option<String> {
	found.iter().find(|c| c.project == project).and_then(|c| c.version.clone())
}

const OPKG: &[u8] = b"Package: busybox\nVersion: 1.36.1-r2\nStatus: install ok installed\n\nPackage: wireless-regdb\nVersion: 2024.10.07\nStatus: install ok installed\n";

#[test]
fn opkg_status_yields_packages_without_the_revision() {
	let found = components(&[("usr/lib/opkg/status", OPKG)]);
	// -r2 is the packaging revision, not part of the upstream release.
	assert_eq!(version_of(&found, "busybox"), Some("1.36.1".into()), "{found:?}");
	assert_eq!(version_of(&found, "wireless-regdb"), Some("2024.10.07".into()), "{found:?}");
}

#[test]
fn dpkg_source_field_names_the_upstream_project() {
	// zlib1g is the Debian binary package; zlib is the project a CVE is filed against.
	let db = b"Package: zlib1g\nSource: zlib\nVersion: 1:1.2.8.dfsg-5\nStatus: install ok installed\n";
	let found = components(&[("var/lib/dpkg/status", db)]);
	assert_eq!(version_of(&found, "zlib"), Some("1.2.8".into()), "{found:?}");
	assert!(!found.iter().any(|c| c.project == "zlib1g"), "counted twice: {found:?}");
}

#[test]
fn removed_packages_are_not_reported_as_present() {
	// dpkg keeps a stanza for a package whose config files survived removal.
	let db = b"Package: telnetd\nVersion: 0.17-40\nStatus: deinstall ok config-files\n";
	let found = components(&[("var/lib/dpkg/status", db)]);
	assert!(!found.iter().any(|c| c.project == "telnetd"), "{found:?}");
}

#[test]
fn evidence_records_the_database_as_the_source() {
	let found = components(&[("usr/lib/opkg/status", OPKG)]);
	let busybox = found.iter().find(|c| c.project == "busybox").expect("busybox");
	assert!(
		busybox.evidence.iter().any(|e| e.kind == felf_core::EvidenceKind::PackageDatabase),
		"a database claim must say so: {busybox:?}"
	);
}

#[test]
fn a_status_file_elsewhere_is_not_a_package_database() {
	// Firmware is full of files called "status". Only the two real locations count.
	let found = components(&[("etc/status", OPKG), ("var/run/status", OPKG)]);
	assert!(found.is_empty(), "{found:?}");
}
