//! Grades the analyzer against Alpine packages whose filenames carry exact upstream
//! versions. Ground truth is project -> SET of versions: a tree can legitimately contain
//! two generations of one library, and collapsing them scores a correct answer as wrong.
//!
//! Ignored by default: the corpus is too large to ship. Run the gate with
//! `FELF_GROUNDTRUTH=<corpus root> cargo test --release -- --ignored`
//! (see research/build_groundtruth.py). Asked for explicitly, a missing corpus is a
//! failure — a gate that reports a pass without running is worse than no gate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use felf_core::store::Store;
use felf_identify::Analyzer;

const TRUTH: &str = include_str!("fixtures/alpine_groundtruth.tsv");

fn numeric_prefix(v: &str) -> String {
	let mut out = String::new();
	for c in v.chars() {
		if c.is_ascii_digit() || (c == '.' && !out.is_empty()) {
			out.push(c);
		} else {
			break;
		}
	}
	out.trim_end_matches('.').to_string()
}

fn compatible(claim: &str, truth: &str) -> bool {
	claim == truth || claim.starts_with(truth) || truth.starts_with(claim)
}

fn load(root: &Path, store: &mut Store) {
	let Ok(entries) = std::fs::read_dir(root) else { return };
	for entry in entries.flatten() {
		let path = entry.path();
		let Ok(meta) = entry.metadata() else { continue };
		if meta.is_symlink() {
			continue;
		}
		if meta.is_dir() {
			load(&path, store);
		} else if let Ok(bytes) = std::fs::read(&path) {
			store.insert(path.clone(), bytes);
		}
	}
}

#[test]
#[ignore = "requires FELF_GROUNDTRUTH; run with --ignored"]
fn precision_against_alpine_ground_truth() {
	let root = match std::env::var("FELF_GROUNDTRUTH") {
		Ok(root) => PathBuf::from(root),
		Err(_) => panic!("FELF_GROUNDTRUTH unset; see research/build_groundtruth.py"),
	};
	assert!(root.is_dir(), "FELF_GROUNDTRUTH={} is not a directory", root.display());

	let mut truth: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
	for line in TRUTH.lines() {
		let mut f = line.split('\t');
		let (Some(rel), Some(project), Some(version)) = (f.next(), f.next(), f.next()) else {
			continue;
		};
		truth
			.entry((rel.to_string(), project.to_string()))
			.or_default()
			.insert(numeric_prefix(version));
	}

	let releases: BTreeSet<&String> = truth.keys().map(|(rel, _)| rel).collect();
	let (mut claims, mut correct, mut ground) = (0usize, 0usize, 0usize);
	let mut wrong = Vec::new();

	for rel in releases {
		let dir = root.join(rel);
		if !dir.is_dir() {
			continue;
		}
		let mut store = Store::new();
		load(&dir, &mut store);
		let components = Analyzer::new().analyze(&store);

		let expected: BTreeMap<&String, &BTreeSet<String>> = truth
			.iter()
			.filter(|((r, _), _)| r == rel)
			.map(|((_, p), v)| (p, v))
			.collect();
		ground += expected.len();

		for c in components.iter().filter(|c| c.is_versioned()) {
			let Some(versions) = expected.get(&c.project) else { continue };
			let claim = numeric_prefix(c.version.as_deref().unwrap_or_default());
			claims += 1;
			if versions.iter().any(|t| compatible(&claim, t)) {
				correct += 1;
			} else {
				wrong.push(format!("{rel} {} claimed {claim}, truth {versions:?}", c.project));
			}
		}
	}

	assert!(claims > 0, "no ground-truth trees found under {}", root.display());
	let precision = 100.0 * correct as f64 / claims as f64;
	let recall = 100.0 * claims as f64 / ground as f64;
	println!("ground truth {ground}  claims {claims}  correct {correct}");
	println!("precision {precision:.1}%  version recall {recall:.1}%");
	for w in &wrong {
		println!("WRONG: {w}");
	}

	// A wrong version is a false statement in a signed declaration; silence is a
	// declarable gap. Precision must not regress, recall is allowed to improve.
	assert!(wrong.is_empty(), "precision regressed: {wrong:?}");
	assert!(recall >= 40.0, "version recall dropped below 40%: {recall:.1}%");
}
