//! A manifest says what the build shipped. These cover the three formats it arrives in and
//! the one thing the comparison must never do: claim absence, or claim agreement it did not
//! establish.

use felf_core::{Component, Confidence, Evidence, EvidenceKind};
use felf_identify::manifest::{parse, reconcile, Format};

fn component(project: &str, version: Option<&str>, kind: EvidenceKind) -> Component {
	Component {
		project: project.into(),
		version: version.map(Into::into),
		cpes: Vec::new(),
		purl: None,
		confidence: Confidence::Confirmed,
		evidence: vec![Evidence {
			kind,
			path: format!("usr/lib/lib{project}.so").into(),
			offset: None,
			value: version.unwrap_or_default().into(),
			confidence: Confidence::Confirmed,
		}],
	}
}

#[test]
fn openwrt_manifest_drops_the_package_revision() {
	let (format, declared) = parse(b"busybox - 1.36.1-r2\nwireless-regdb - 2024.10.07\n");
	assert_eq!(format, Format::OpenWrt);
	assert_eq!(declared.len(), 2);
	assert_eq!(declared[0].project, "busybox");
	assert_eq!(declared[0].version.as_deref(), Some("1.36.1"));
	assert_eq!(declared[1].version.as_deref(), Some("2024.10.07"));
}

#[test]
fn control_manifest_uses_the_source_field() {
	let db = b"Package: zlib1g\nSource: zlib\nVersion: 1:1.2.8.dfsg-5\nStatus: install ok installed\n";
	let (format, declared) = parse(db);
	assert_eq!(format, Format::Control);
	assert_eq!(declared[0].project, "zlib");
	assert_eq!(declared[0].version.as_deref(), Some("1.2.8"));
}

#[test]
fn a_generic_manifest_keeps_the_version_verbatim() {
	// Nothing is known about the convention that produced this file, so stripping a
	// trailing field would turn a beta into a claim about the release.
	let (format, declared) = parse(b"openssl 1.0.2-beta1\nzlib 1.2.11\n");
	assert_eq!(format, Format::Generic);
	assert_eq!(declared[0].version.as_deref(), Some("1.0.2-beta1"));
	assert_eq!(declared[1].version.as_deref(), Some("1.2.11"));
}

#[test]
fn buckets_split_declared_and_observed() {
	let (_, declared) = parse(b"busybox - 1.36.1-r2\nuboot-envtools - 2024.07\n");
	let observed = [
		component("busybox", Some("1.36.1"), EvidenceKind::VersionString),
		component("mbedtls", Some("3.6.2"), EvidenceKind::VersionString),
	];
	let r = reconcile(&declared, &observed);

	assert_eq!(r.corroborated.len(), 1);
	assert_eq!(r.corroborated[0].project, "busybox");
	assert_eq!(r.corroborated[0].agrees, Some(true));

	// Declared with nothing supporting it. Not a claim that it is absent.
	assert_eq!(r.uncorroborated.len(), 1);
	assert_eq!(r.uncorroborated[0].raw, "uboot-envtools");

	// Found, but no manifest entry of that name. A naming question.
	assert_eq!(r.unmatched, vec!["mbedtls".to_string()]);
}

#[test]
fn a_refinement_is_agreement_but_a_different_release_is_not() {
	let (_, declared) = parse(b"openssl 1.0.2\ncurl 7.61.1\n");
	let observed = [
		component("openssl", Some("1.0.2u"), EvidenceKind::VersionString),
		component("curl", Some("7.36.0"), EvidenceKind::VersionString),
	];
	let r = reconcile(&declared, &observed);
	let agrees = |p: &str| {
		r.corroborated.iter().find(|c| c.project == p).and_then(|c| c.agrees)
	};
	assert_eq!(agrees("openssl"), Some(true), "1.0.2u refines 1.0.2");
	assert_eq!(agrees("curl"), Some(false), "7.36.0 is not 7.61.1");
	assert_eq!(r.disagreements().count(), 1);
}

#[test]
fn nothing_is_compared_when_a_version_is_missing() {
	let (_, declared) = parse(b"openssl 1.0.2u\nzlib\n");
	let observed = [
		component("openssl", None, EvidenceKind::Soname),
		component("zlib", Some("1.2.11"), EvidenceKind::VersionString),
	];
	let r = reconcile(&declared, &observed);
	assert!(r.corroborated.iter().all(|c| c.agrees.is_none()), "{:?}", r.corroborated);
}

#[test]
fn database_only_support_is_distinguished_from_evidence_in_the_bytes() {
	// The image's own package database and the build manifest come from the same build.
	// Agreement between them corroborates very little, so it must be countable separately.
	let (_, declared) = parse(b"busybox - 1.36.1-r2\ndnsmasq - 2.90-r4\n");
	let observed = [
		component("busybox", Some("1.36.1"), EvidenceKind::PackageDatabase),
		component("dnsmasq", Some("2.90"), EvidenceKind::VersionString),
	];
	let r = reconcile(&declared, &observed);
	let from_bytes: Vec<&str> =
		r.corroborated.iter().filter(|c| c.from_bytes()).map(|c| c.project.as_str()).collect();
	assert_eq!(from_bytes, vec!["dnsmasq"], "{:?}", r.corroborated);
}
