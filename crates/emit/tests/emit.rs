use felf_core::{Component, Confidence, Evidence, EvidenceKind, Inventory};
use felf_emit::{cyclonedx, report, serial_for, timestamp};

fn sample() -> Inventory {
	let mut inv = Inventory::default();
	inv.components.push(Component {
		project: "curl".into(),
		version: Some("7.36.0".into()),
		cpes: vec![
			"cpe:2.3:a:haxx:curl:7.36.0:*:*:*:*:*:*:*".into(),
			"cpe:2.3:a:haxx:libcurl:7.36.0:*:*:*:*:*:*:*".into(),
		],
		purl: Some("pkg:generic/curl@7.36.0".into()),
		confidence: Confidence::Confirmed,
		evidence: vec![Evidence {
			kind: EvidenceKind::VersionString,
			path: "usr/lib/libcurl.so".into(),
			offset: None,
			value: "7.36.0".into(),
			confidence: Confidence::Confirmed,
		}],
	});
	inv.gap("firmware.bin", "encrypted, no key supplied");
	inv
}

#[test]
fn cyclonedx_carries_aliases_and_gaps() {
	let doc = cyclonedx::build(&sample(), "firmware.bin", &timestamp(), &serial_for("x"));
	assert_eq!(doc["specVersion"], "1.6");
	let c = &doc["components"][0];
	assert_eq!(c["name"], "curl");
	assert_eq!(c["cpe"], "cpe:2.3:a:haxx:curl:7.36.0:*:*:*:*:*:*:*");
	let props = c["properties"].as_array().unwrap();
	assert!(props.iter().any(|p| p["name"] == "felf:cpe-alias"));
	let gaps = doc["metadata"]["properties"].as_array().unwrap();
	assert!(gaps.iter().any(|g| g["name"] == "felf:coverage-gap"));
}

#[test]
fn evidence_is_deduplicated() {
	let mut inv = sample();
	let dup = inv.components[0].evidence[0].clone();
	inv.components[0].evidence.push(dup);
	let doc = cyclonedx::build(&inv, "f", &timestamp(), &serial_for("x"));
	let methods = doc["components"][0]["evidence"]["identity"][0]["methods"].as_array().unwrap();
	assert_eq!(methods.len(), 1);
}

#[test]
fn serial_is_uuid_v4_shaped() {
	let s = serial_for("firmware.bin");
	let parts: Vec<&str> = s.split('-').collect();
	assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), vec![8, 4, 4, 4, 12]);
	assert!(s.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
	assert!(parts[2].starts_with('4'));
	assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
}

#[test]
fn serial_is_stable() {
	assert_eq!(serial_for("a.bin"), serial_for("a.bin"));
	assert_ne!(serial_for("a.bin"), serial_for("b.bin"));
}

#[test]
fn timestamp_is_rfc3339_shaped() {
	let t = timestamp();
	assert_eq!(t.len(), 20);
	assert!(t.ends_with('Z') && t.contains('T'));
	let year: i64 = t[..4].parse().unwrap();
	assert!((2024..2100).contains(&year), "implausible year {year}");
}

#[test]
fn report_escapes_and_states_limits() {
	let mut inv = sample();
	inv.components[0].project = "<script>".into();
	let html = report::build(&inv, "f", &timestamp(), Some(3));
	assert!(html.contains("&lt;script&gt;"));
	assert!(!html.contains("<script>"));
	assert!(html.contains("not a vulnerability assessment"));
	assert!(html.contains("Coverage gaps"));
	assert!(html.contains("Your current SBOM lists"));
}

#[test]
fn empty_inventory_still_documents_the_gap() {
	let mut inv = Inventory::default();
	inv.gap("f.bin", "encrypted, no key supplied");
	let doc = cyclonedx::build(&inv, "f.bin", &timestamp(), &serial_for("f"));
	assert_eq!(doc["components"].as_array().unwrap().len(), 0);
	assert_eq!(doc["metadata"]["properties"].as_array().unwrap().len(), 1);
	let html = report::build(&inv, "f.bin", &timestamp(), None);
	assert!(html.contains("Coverage gaps"));
}
