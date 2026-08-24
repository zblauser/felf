use felf_core::bytes::find;
use thiserror::Error;

pub mod archive;
pub mod container;
pub mod lzma;
pub mod squashfs;

#[derive(Debug, Error)]
pub enum UnpackError {
	#[error("input truncated")]
	Truncated,
	#[error("not a squashfs image")]
	NotSquashFs,
	#[error("unsupported compressor: {0}")]
	UnsupportedCompressor(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
	SquashFs,
	CramFs,
	Ubi,
	Jffs2,
	Cpio,
}

impl FsKind {
	pub fn name(&self) -> &'static str {
		match self {
			FsKind::SquashFs => "squashfs",
			FsKind::CramFs => "cramfs",
			FsKind::Ubi => "ubi",
			FsKind::Jffs2 => "jffs2",
			FsKind::Cpio => "cpio",
		}
	}
}

/// Kernels embed the literal string "070701" in their own initramfs parser diagnostics,
/// so a cpio signature is only believable if the header behind it parses as hex.
fn plausible_cpio(data: &[u8], offset: usize) -> bool {
	let Some(h) = data.get(offset..offset + 110) else { return false };
	h[6..110].iter().all(|b| b.is_ascii_hexdigit())
}

/// Entropy over a sample of the image. Encrypted and fully-compressed payloads sit at ~8.0;
/// a filesystem with text and headers sits well below.
pub fn entropy(data: &[u8]) -> f64 {
	let sample = &data[..data.len().min(1 << 20)];
	if sample.is_empty() {
		return 0.0;
	}
	let mut counts = [0usize; 256];
	for b in sample {
		counts[*b as usize] += 1;
	}
	let len = sample.len() as f64;
	-counts
		.iter()
		.filter(|c| **c > 0)
		.map(|c| {
			let p = *c as f64 / len;
			p * p.log2()
		})
		.sum::<f64>()
}

/// Vendor encryption wrappers seen in the corpus. Recognising them lets the tool say
/// "encrypted, no key supplied" instead of "no filesystem found", which is a materially
/// different statement to put in a compliance document. Note these are not unopenable:
/// public keys exist for several SHRS models and for a range of DSM releases.
pub fn encrypted_marker(data: &[u8]) -> Option<&'static str> {
	const MAGICS: [(&[u8], &str); 3] = [
		(b"SHRS", "D-Link SHRS encrypted container"),
		(&[0x2d, 0xad, 0xbe, 0xef], "Synology encrypted .pat"),
		(b"ENCRYPTED", "vendor-marked encrypted image"),
	];
	MAGICS
		.iter()
		.find(|(m, _)| data.starts_with(m))
		.map(|(_, label)| *label)
}

pub fn find_filesystems(data: &[u8]) -> Vec<(usize, FsKind)> {
	const SIGS: [(&[u8], FsKind); 5] = [
		(b"hsqs", FsKind::SquashFs),
		(&[0x45, 0x3D, 0xCD, 0x28], FsKind::CramFs),
		(b"UBI#", FsKind::Ubi),
		(&[0x85, 0x19, 0x03, 0x20], FsKind::Jffs2),
		(b"070701", FsKind::Cpio),
	];
	let mut hits = Vec::new();
	for (sig, kind) in SIGS {
		let mut from = 0usize;
		while let Some(rel) = find(&data[from..], sig) {
			let at = from + rel;
			if kind != FsKind::Cpio || plausible_cpio(data, at) {
				hits.push((at, kind));
			}
			from += rel + sig.len();
			if hits.len() > 64 {
				break;
			}
		}
	}
	hits.sort_by_key(|(off, _)| *off);
	hits
}

