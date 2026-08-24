use std::fmt::Write;

use felf_core::{Component, Inventory};

fn escape(s: &str) -> String {
	s.chars()
		.map(|c| match c {
			'&' => "&amp;".into(),
			'<' => "&lt;".into(),
			'>' => "&gt;".into(),
			'"' => "&quot;".into(),
			other => other.to_string(),
		})
		.collect()
}

fn evidence_summary(c: &Component) -> String {
	let mut kinds: Vec<String> = c.evidence.iter().map(|e| format!("{:?}", e.kind)).collect();
	kinds.sort();
	kinds.dedup();
	kinds.join(", ")
}

/// `baseline` is the component count from whatever SBOM the customer already has. The
/// delta is the point of the document: it is what gets forwarded to whoever signs.
pub fn build(inventory: &Inventory, subject: &str, timestamp: &str, baseline: Option<usize>) -> String {
	let versioned = inventory.versioned();
	let total = inventory.components.len();
	let mut h = String::new();

	let _ = write!(
		h,
		r#"<!doctype html><meta charset="utf-8"><title>Firmware inventory — {subject}</title>
<style>
:root{{color-scheme:light dark}}
body{{font:15px/1.55 ui-sans-serif,system-ui,sans-serif;margin:0;padding:2.5rem 1.5rem;
background:Canvas;color:CanvasText}}
main{{max-width:60rem;margin:0 auto}}
h1{{font-size:1.35rem;margin:0 0 .25rem}}
.sub{{opacity:.7;font-size:.85rem;margin-bottom:2rem}}
.delta{{border:1px solid color-mix(in srgb,CanvasText 20%,transparent);border-radius:.5rem;
padding:1.25rem 1.5rem;margin-bottom:2rem}}
.big{{font-size:2rem;font-weight:600}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}
th,td{{text-align:left;padding:.45rem .6rem;border-bottom:1px solid
color-mix(in srgb,CanvasText 12%,transparent);vertical-align:top}}
th{{font-weight:600;opacity:.75;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}}
code{{font:13px ui-monospace,monospace}}
.muted{{opacity:.55}}
.gap{{border-left:3px solid #b45309;padding:.5rem .85rem;margin:.4rem 0;
background:color-mix(in srgb,#b45309 8%,transparent);font-size:.88rem}}
footer{{margin-top:2.5rem;padding-top:1.25rem;border-top:1px solid
color-mix(in srgb,CanvasText 12%,transparent);font-size:.85rem;opacity:.75}}
</style>
<main>
<h1>Firmware component inventory</h1>
<div class="sub"><code>{subject}</code> · {timestamp} · felf {version}</div>
"#,
		subject = escape(subject),
		timestamp = escape(timestamp),
		version = env!("CARGO_PKG_VERSION"),
	);

	let _ = write!(h, r#"<div class="delta">"#);
	match baseline {
		Some(n) => {
			let _ = write!(
				h,
				r#"<div class="big">{total} components found</div>
<div>Your current SBOM lists <strong>{n}</strong>. This firmware contains <strong>{total}</strong>
identifiable upstream components, {versioned} of them with a determined version.</div>"#
			);
		}
		None => {
			let _ = write!(
				h,
				r#"<div class="big">{total} components found</div>
<div>{versioned} with a determined version.</div>"#
			);
		}
	}
	let _ = write!(h, "</div>");

	if !inventory.gaps.is_empty() {
		let _ = write!(h, "<h2>Coverage gaps</h2><p class=\"muted\">Regions that could not be read. Declared rather than omitted — an inventory that hides what it could not see is not verifiable.</p>");
		for g in &inventory.gaps {
			let _ = write!(h, r#"<div class="gap">{}</div>"#, escape(&g.reason));
		}
	}

	let _ = write!(
		h,
		"<h2>Components</h2><table><tr><th>component</th><th>version</th><th>confidence</th><th>identifier</th><th>evidence</th></tr>"
	);
	for c in &inventory.components {
		let _ = write!(
			h,
			"<tr><td>{}</td><td>{}</td><td>{}</td><td><code class=\"muted\">{}</code></td><td class=\"muted\">{}</td></tr>",
			escape(&c.project),
			c.version.as_deref().map(escape).unwrap_or_else(|| "<span class=\"muted\">—</span>".into()),
			c.confidence,
			escape(c.purl.as_deref().unwrap_or("")),
			escape(&evidence_summary(c)),
		);
	}
	let _ = write!(h, "</table>");

	let _ = write!(
		h,
		r#"<footer>
<strong>What this document does and does not claim.</strong>
It states which upstream components are present in the image and, where determinable, at
which version. Components listed without a version were identified but could not be
versioned from the binary; they contribute no vulnerability findings.
This is an inventory, not a vulnerability assessment: it does not claim any listed
component is exploitable in this device.
</footer></main>"#
	);
	h
}
