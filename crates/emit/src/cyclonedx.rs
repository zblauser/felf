use felf_core::{Component, Confidence, EvidenceKind, Inventory};
use serde_json::{json, Map, Value};

/// CycloneDX 1.6 `evidence.identity.methods[].technique` values.
fn technique(kind: &EvidenceKind) -> &'static str {
	match kind {
		EvidenceKind::PackageDatabase => "manifest-analysis",
		EvidenceKind::PackageFilename | EvidenceKind::Soname => "filename",
		EvidenceKind::VersionString | EvidenceKind::BuildPath | EvidenceKind::ElfComment => {
			"binary-analysis"
		}
		EvidenceKind::ContentMarker => "binary-analysis",
	}
}

fn weight(confidence: Confidence) -> f64 {
	match confidence {
		Confidence::Confirmed => 0.9,
		Confidence::Likely => 0.6,
		Confidence::Possible => 0.3,
	}
}

fn component_json(c: &Component, index: usize) -> Value {
	let mut obj = Map::new();
	obj.insert("type".into(), json!("library"));
	obj.insert("bom-ref".into(), json!(format!("felf-{index}")));
	obj.insert("name".into(), json!(c.project));
	if let Some(v) = &c.version {
		obj.insert("version".into(), json!(v));
	}
	if let Some(p) = &c.purl {
		obj.insert("purl".into(), json!(p));
	}
	if let Some(cpe) = c.cpes.first() {
		obj.insert("cpe".into(), json!(cpe));
	}

	// Every additional CPE alias is carried as a property: NVD files one project under
	// several vendor:product pairs and a consumer matching on only `cpe` loses findings.
	let mut properties: Vec<Value> = c.cpes
		.iter()
		.skip(1)
		.map(|cpe| json!({"name": "felf:cpe-alias", "value": cpe}))
		.collect();
	properties.push(json!({"name": "felf:confidence", "value": c.confidence.to_string()}));

	let mut seen_methods: Vec<(String, String)> = Vec::new();
	let methods: Vec<Value> = c
		.evidence
		.iter()
		.filter_map(|e| {
			let key = (
				technique(&e.kind).to_string(),
				format!("{}: {} ({})", e.kind.label(), e.value, e.path.display()),
			);
			if seen_methods.contains(&key) {
				return None;
			}
			seen_methods.push(key.clone());
			Some(json!({
				"technique": key.0,
				"confidence": weight(e.confidence),
				"value": key.1,
			}))
		})
		.collect();

	let occurrences: Vec<Value> = {
		let mut seen: Vec<String> = c
			.evidence
			.iter()
			.map(|e| e.path.display().to_string())
			.collect();
		seen.sort();
		seen.dedup();
		seen.into_iter().map(|l| json!({"location": l})).collect()
	};

	if !methods.is_empty() {
		obj.insert(
			"evidence".into(),
			json!({
				"identity": [{
					"field": if c.version.is_some() { "version" } else { "name" },
					"confidence": weight(c.confidence),
					"methods": methods,
				}],
				"occurrences": occurrences,
			}),
		);
	}
	obj.insert("properties".into(), json!(properties));
	Value::Object(obj)
}

pub fn build(inventory: &Inventory, subject: &str, timestamp: &str, serial: &str) -> Value {
	let components: Vec<Value> = inventory
		.components
		.iter()
		.enumerate()
		.map(|(i, c)| component_json(c, i))
		.collect();

	// CycloneDX has no field for "a region I could not read". Omitting them would make an
	// incomplete document look complete, which is the failure this tool exists to fix.
	let gaps: Vec<Value> = inventory
		.gaps
		.iter()
		.map(|g| json!({"name": "felf:coverage-gap", "value": g.reason}))
		.collect();

	json!({
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": format!("urn:uuid:{serial}"),
		"version": 1,
		"metadata": {
			"timestamp": timestamp,
			"tools": {
				"components": [{
					"type": "application",
					"name": "felf",
					"version": env!("CARGO_PKG_VERSION"),
				}]
			},
			"component": {
				"type": "firmware",
				"bom-ref": "subject",
				"name": subject,
			},
			"properties": gaps,
		},
		"components": components,
	})
}
