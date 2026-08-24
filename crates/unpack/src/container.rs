/// Vendor wrappers sit in front of the real image. Netgear CHK and Broadcom TRX both
/// appear in the corpus; binwalk reports the header and does not recurse past it.
#[derive(Debug, Clone)]
pub struct Peeled {
	pub data: Vec<u8>,
	pub note: String,
}

use felf_core::bytes;

use crate::archive;

/// Vendors nest: zip -> .chk -> TRX -> squashfs, or tar -> squashfs.tmp. Peeling stops at
/// the first layer that yields a filesystem signature, so ordering matters less than
/// covering every wrapper seen in the corpus.
pub fn peel(data: &[u8]) -> Vec<Peeled> {
	if let Some(inner) = archive::gunzip(data) {
		return relabel(peel(&inner), "gzip");
	}
	if archive::is_zip(data) {
		if let Some(m) = largest(archive::unzip(data)) {
			return relabel(peel(&m.data), &format!("zip:{}", m.name));
		}
	}
	if archive::is_tar(data) {
		if let Some(m) = largest(archive::untar(data)) {
			return relabel(peel(&m.data), &format!("tar:{}", m.name));
		}
	}
	// The raw image comes first: a uImage kernel often sits alongside the rootfs rather
	// than containing it, and substituting the payload loses the filesystem entirely.
	let mut out = peel_headers(data);
	if let Some(inner) = uimage_payload(data) {
		out.extend(relabel(peel_headers(&inner.data), &inner.note));
	}
	out
}

struct UImage {
	data: Vec<u8>,
	note: String,
}

/// u-boot legacy uImage. The interesting payload is usually the largest one in the image,
/// not the first: a flash dump often leads with a small standalone bootloader program.
fn uimage_payload(data: &[u8]) -> Option<UImage> {
	const MAGIC: [u8; 4] = [0x27, 0x05, 0x19, 0x56];
	let mut best: Option<UImage> = None;
	let mut pos = 0usize;
	while pos + 64 <= data.len() {
		if data[pos..pos + 4] != MAGIC {
			pos += 4;
			continue;
		}
		let size = bytes::be32(data, pos + 12)? as usize;
		let comp = data[pos + 31];
		let body = pos + 64;
		if size == 0 || body + size > data.len() {
			pos += 4;
			continue;
		}
		let raw = &data[body..body + size];
		let limit = 256 << 20;
		let payload = match comp {
			0 => Some(raw.to_vec()),
			1 => archive::gunzip(raw),
			3 => crate::lzma::decode_alone(raw, limit),
			_ => None,
		};
		if let Some(payload) = payload {
			let better = best.as_ref().is_none_or(|b| payload.len() > b.data.len());
			if better {
				best = Some(UImage {
					note: format!("uImage@{pos:#x} comp={comp} {}B", payload.len()),
					data: payload,
				});
			}
		}
		pos = body + size;
	}
	best
}

fn largest(members: Vec<archive::Member>) -> Option<archive::Member> {
	members.into_iter().max_by_key(|m| m.data.len())
}

fn relabel(peeled: Vec<Peeled>, outer: &str) -> Vec<Peeled> {
	peeled
		.into_iter()
		.map(|p| Peeled { note: format!("{outer} > {}", p.note), data: p.data })
		.collect()
}

fn peel_headers(data: &[u8]) -> Vec<Peeled> {
	if bytes::be32(data, 0) == Some(0x2a23_245e) && data.len() >= 8 {
		let len = bytes::be32(data, 4).unwrap_or(0) as usize;
		if len < data.len() {
			let inner = peel_headers(&data[len..]);
			if !inner.is_empty() {
				return inner;
			}
		}
	}
	if data.len() >= 28 && &data[0..4] == b"HDR0" {
		let mut out = Vec::new();
		for i in 0..3 {
			let base = 16 + i * 4;
			let off = bytes::le32(data, base).unwrap_or(0) as usize;
			if off > 0 && off < data.len() {
				out.push(Peeled {
					data: data[off..].to_vec(),
					note: format!("TRX partition {i} at {off}"),
				});
			}
		}
		if !out.is_empty() {
			return out;
		}
	}
	vec![Peeled { data: data.to_vec(), note: "no wrapper".into() }]
}
