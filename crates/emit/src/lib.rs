pub mod cyclonedx;
pub mod report;

/// RFC 3339 timestamp without pulling in a date crate.
pub fn timestamp() -> String {
	let secs = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let days = secs / 86_400;
	let (h, m, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
	let (y, mo, d) = civil_from_days(days as i64);
	format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's days-from-civil, inverted.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
	let z = z + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z.rem_euclid(146_097);
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
	(if m <= 2 { y + 1 } else { y }, m, d)
}

/// Deterministic pseudo-UUID from the subject: reruns over the same image produce the same
/// serial, so two reports can be diffed without spurious churn.
pub fn serial_for(subject: &str) -> String {
	let h = felf_core::hash(subject.as_bytes());
	// Shape it as RFC 4122 v4 so CycloneDX validators accept the serialNumber.
	let variant = match &h[16..17] {
		"0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => "8",
		"8" | "9" | "a" | "b" => "9",
		_ => "a",
	};
	format!("{}-{}-4{}-{}{}-{}", &h[0..8], &h[8..12], &h[13..16], variant, &h[17..20], &h[20..32])
}
