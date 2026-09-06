use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use felf_core::{store::Store, Inventory};
use felf_identify::Analyzer;
use felf_unpack::{archive, container, find_filesystems, squashfs::SquashFs, FsKind};

#[derive(Parser)]
#[command(name = "felf", version, about = "firmware component inventory")]
struct Cli {
	#[command(subcommand)]
	cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
	/// Extract a firmware image
	Unpack {
		image: PathBuf,
		#[arg(short, long)]
		out: Option<PathBuf>,
	},
	/// Compare a build manifest against what the image actually supports
	Reconcile {
		image: PathBuf,
		/// Manifest the build system produced: opkg/dpkg control, OpenWrt, or two columns
		#[arg(long, value_name = "FILE")]
		manifest: PathBuf,
		/// List components found in the image that matched no manifest entry by name
		#[arg(long)]
		unmatched: bool,
		/// List manifest entries with nothing in the image supporting them
		#[arg(long)]
		uncorroborated: bool,
	},
	/// Extract and inventory components
	Scan {
		image: PathBuf,
		/// Also list components that were identified but could not be versioned
		#[arg(long)]
		unversioned: bool,
		/// Write a CycloneDX 1.6 SBOM
		#[arg(long, value_name = "FILE")]
		sbom: Option<PathBuf>,
		/// Write a self-contained HTML report
		#[arg(long, value_name = "FILE")]
		report: Option<PathBuf>,
		/// Component count from the SBOM you already have, for the delta
		#[arg(long, value_name = "N")]
		baseline: Option<usize>,
	},
}

fn main() -> Result<()> {
	match Cli::parse().cmd {
		Cmd::Unpack { image, out } => unpack(image, out),
		Cmd::Reconcile { image, manifest, unmatched, uncorroborated } => {
			reconcile(image, manifest, unmatched, uncorroborated)
		}
		Cmd::Scan { image, unversioned, sbom, report, baseline } => {
			scan(image, unversioned, sbom, report, baseline)
		}
	}
}

struct Extracted {
	store: Store,
	inventory: Inventory,
	note: String,
	compressor: String,
	declared_inodes: u32,
}

fn load_dir(root: &Path) -> Result<Extracted> {
	let mut store = Store::new();
	let mut stack = vec![root.to_path_buf()];
	while let Some(dir) = stack.pop() {
		for entry in fs::read_dir(&dir)? {
			let entry = entry?;
			let path = entry.path();
			let meta = entry.metadata()?;
			if meta.is_symlink() {
				continue;
			}
			if meta.is_dir() {
				stack.push(path);
			} else if let Ok(bytes) = fs::read(&path) {
				let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
				store.insert(rel, bytes);
			}
		}
	}
	Ok(Extracted {
		store,
		inventory: Inventory::default(),
		note: format!("directory {}", root.display()),
		compressor: "n/a".into(),
		declared_inodes: 0,
	})
}

fn extract(image: &Path) -> Result<Extracted> {
	if image.is_dir() {
		return load_dir(image);
	}
	let raw = fs::read(image)?;
	let mut inventory = Inventory::default();
	let mut store = Store::new();
	let mut note = String::new();
	let mut compressor = String::new();
	let mut declared_inodes = 0;

	'outer: for peeled in container::peel(&raw) {
		let signatures = find_filesystems(&peeled.data);
		if signatures.is_empty() && peeled.note.contains("uImage") {
			inventory.gap(
				image,
				format!("{} decompressed but contains no filesystem — kernel-only image", peeled.note),
			);
		}
		for (offset, kind) in signatures {
			if kind == FsKind::Cpio {
				let members = felf_unpack::archive::uncpio(&peeled.data[offset..]);
				if members.len() > 4 {
					for m in &members {
						store.insert(&m.name, m.data.clone());
					}
					note = format!("{} > cpio@{offset:#x}", peeled.note);
					compressor = "cpio".into();
					declared_inodes = members.len() as u32;
					break 'outer;
				}
				continue;
			}
			if kind != FsKind::SquashFs {
				inventory.gap(image, format!("{} at {offset} not yet supported", kind.name()));
				continue;
			}
			let Ok(mut fs) = SquashFs::parse(&peeled.data[offset..]) else { continue };
			let entries = fs.walk();
			if entries.is_empty() {
				inventory.gap(
					image,
					format!("squashfs/{} at {offset} yielded no files", fs.sb.compressor.name()),
				);
				continue;
			}
			for e in &entries {
				store.insert(&e.path, e.data.clone());
			}
			note = peeled.note.clone();
			compressor = fs.sb.compressor.name();
			declared_inodes = fs.sb.inodes;
			break 'outer;
		}
	}

	if store.is_empty() {
		if let Some(label) = felf_unpack::encrypted_marker(&raw) {
			inventory.gap(image, format!("{label} — encrypted, no key supplied"));
		} else if felf_unpack::entropy(&raw) > 7.9 {
			inventory.gap(image, "high entropy throughout, no parseable structure — likely encrypted");
		} else if inventory.gaps.is_empty() {
			inventory.gap(image, "no recognised filesystem or container format");
		}
		note = "not extracted".into();
	}
	Ok(Extracted { store, inventory, note, compressor, declared_inodes })
}

/// Vendors ship whole filesystems inside a single file — 21MB of the R7000 is one
/// `bitdefender.tar`. Treating that as one artifact both hides its contents and makes the
/// several versions it contains look like contradictory evidence about one binary.
fn expand_nested(store: &mut Store) {
	let candidates: Vec<(PathBuf, Vec<u8>)> = store
		.paths()
		.filter(|p| {
			store.get(p).is_some_and(|d| {
				d.len() > 4096 && (archive::is_tar(d) || archive::is_zip(d) || d.starts_with(&[0x1f, 0x8b]))
			})
		})
		.map(|p| (p.clone(), store.get(p).unwrap_or_default().to_vec()))
		.collect();

	for (path, data) in candidates {
		let inner = if let Some(gz) = archive::gunzip(&data) {
			if archive::is_tar(&gz) { archive::untar(&gz) } else { Vec::new() }
		} else if archive::is_tar(&data) {
			archive::untar(&data)
		} else {
			archive::unzip(&data)
		};
		for m in inner {
			store.insert(path.join(&m.name), m.data);
		}
	}
}

fn unpack(image: PathBuf, out: Option<PathBuf>) -> Result<()> {
	let e = extract(&image)?;
	if e.store.is_empty() {
		for gap in &e.inventory.gaps {
			eprintln!("gap: {}", gap.reason);
		}
		bail!("no filesystem extracted");
	}
	report_extraction(&e);
	if let Some(dir) = out {
		for path in e.store.paths() {
			let Some(data) = e.store.get(path) else { continue };
			let target = dir.join(path);
			if let Some(parent) = target.parent() {
				fs::create_dir_all(parent)?;
			}
			fs::write(target, data)?;
		}
		println!("wrote {} files to {}", e.store.len(), dir.display());
	}
	Ok(())
}

fn scan(
	image: PathBuf,
	show_unversioned: bool,
	sbom: Option<PathBuf>,
	report: Option<PathBuf>,
	baseline: Option<usize>,
) -> Result<()> {
	let mut e = extract(&image)?;
	if e.store.is_empty() {
		println!("{}  no filesystem extracted", e.note);
	} else {
		report_extraction(&e);
	}

	expand_nested(&mut e.store);
	e.inventory.components = Analyzer::new().analyze(&e.store);
	let components = &e.inventory.components;
	let versioned = e.inventory.versioned();

	let shown: Vec<&felf_core::Component> = components
		.iter()
		.filter(|c| c.is_versioned() || show_unversioned)
		.collect();
	let name_width = shown.iter().map(|c| c.project.len()).max().unwrap_or(0).max(9);
	let version_width = shown
		.iter()
		.map(|c| c.version.as_deref().unwrap_or("-").len())
		.max()
		.unwrap_or(0)
		.max(7);

	println!();
	for c in shown {
		println!(
			"  {:name_width$}  {:version_width$}  {}",
			c.project,
			c.version.as_deref().unwrap_or("-"),
			c.confidence,
		);
	}
	println!(
		"\n{} components, {} versioned, {} unversioned",
		components.len(),
		versioned,
		components.len() - versioned
	);
	for gap in &e.inventory.gaps {
		println!("gap: {}", gap.reason);
	}

	let subject = image.file_name().unwrap_or(image.as_os_str()).to_string_lossy();
	let stamp = felf_emit::timestamp();
	if let Some(path) = sbom {
		let doc = felf_emit::cyclonedx::build(
			&e.inventory,
			&subject,
			&stamp,
			&felf_emit::serial_for(&subject),
		);
		fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
		println!("wrote {}", path.display());
	}
	if let Some(path) = report {
		let html = felf_emit::report::build(&e.inventory, &subject, &stamp, baseline);
		fs::write(&path, html)?;
		println!("wrote {}", path.display());
	}
	Ok(())
}

/// Corroboration, not discrepancy: a manifest entry with no support is reported as
/// unsupported, never as absent, and a component that matched no entry is reported as a
/// name that did not match. Deciding either way needs a package-name to upstream-project
/// mapping that only Debian's `Source:` field supplies.
fn reconcile(
	image: PathBuf,
	manifest: PathBuf,
	show_unmatched: bool,
	show_uncorroborated: bool,
) -> Result<()> {
	let declared_bytes = fs::read(&manifest)?;
	let (format, declared) = felf_identify::manifest::parse(&declared_bytes);
	if declared.is_empty() {
		bail!("no entries parsed from {} as {}", manifest.display(), format.name());
	}

	let mut e = extract(&image)?;
	if e.store.is_empty() {
		println!("{}  no filesystem extracted", e.note);
		for gap in &e.inventory.gaps {
			println!("gap: {}", gap.reason);
		}
		bail!("nothing to compare against");
	}
	report_extraction(&e);
	expand_nested(&mut e.store);
	let observed = Analyzer::new().analyze(&e.store);
	let r = felf_identify::manifest::reconcile(&declared, &observed);

	let from_bytes = r.corroborated.iter().filter(|c| c.from_bytes()).count();
	println!(
		"manifest {}  {} declared ({})",
		manifest.file_name().unwrap_or(manifest.as_os_str()).to_string_lossy(),
		declared.len(),
		format.name()
	);
	println!("image    {} components\n", observed.len());
	let db_only = r.corroborated.len() - from_bytes;
	println!("  corroborated    {:4}  of {} declared", r.corroborated.len(), declared.len());
	println!("     from the bytes             {from_bytes:4}");
	println!("     from the image's own package database only  {db_only:4}");
	if db_only > 0 {
		println!(
			"       that database and the manifest are both products of the same build,\n\
			 \x20      so agreement between them corroborates very little"
		);
	}
	println!("  uncorroborated  {:4}  nothing in the image supports these", r.uncorroborated.len());
	println!("  unmatched       {:4}  found in the image, no manifest entry of that name", r.unmatched.len());

	if from_bytes > 0 {
		println!("\ncorroborated from the bytes");
		for c in r.corroborated.iter().filter(|c| c.from_bytes()) {
			let kinds: Vec<&str> = c.evidence.iter().copied().collect();
			println!(
				"  {:24}  manifest {:16}  image {:16}  {}",
				c.project,
				c.declared.as_deref().unwrap_or("-"),
				if c.observed.is_empty() { "-".into() } else { c.observed.join(", ") },
				kinds.join(", ")
			);
		}
	}

	let disagreements: Vec<_> = r.disagreements().collect();
	if !disagreements.is_empty() {
		println!("\nversion disagreements");
		for c in disagreements {
			println!("  {:24}  manifest {:20}  image {}", c.project, c.declared.as_deref().unwrap_or("-"), c.observed.join(", "));
		}
	}

	if show_uncorroborated && !r.uncorroborated.is_empty() {
		println!("\nuncorroborated — declared, not supported by anything in the image");
		for d in &r.uncorroborated {
			println!("  {:32}  {}", d.raw, d.version.as_deref().unwrap_or("-"));
		}
	}
	if show_unmatched && !r.unmatched.is_empty() {
		println!("\nunmatched — found in the image, no manifest entry of that name");
		for name in &r.unmatched {
			println!("  {name}");
		}
	}
	Ok(())
}

fn report_extraction(e: &Extracted) {
	print!("{}  {} files ({} unique)", e.note, e.store.len(), e.store.unique_blobs());
	if e.declared_inodes > 0 {
		print!("  squashfs {}  {} inodes declared", e.compressor, e.declared_inodes);
	}
	println!();
}
