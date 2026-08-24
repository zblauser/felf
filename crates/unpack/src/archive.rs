use std::io::Read;

use felf_core::bytes;

pub struct Member {
	pub name: String,
	pub data: Vec<u8>,
}

pub fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
	if data.len() < 3 || data[0] != 0x1f || data[1] != 0x8b {
		return None;
	}
	let mut out = Vec::new();
	flate2::read::GzDecoder::new(data).read_to_end(&mut out).ok()?;
	(!out.is_empty()).then_some(out)
}

/// Minimal zip reader: walks local file headers rather than the central directory, which
/// keeps it tolerant of the truncated archives vendors sometimes publish.
pub fn unzip(data: &[u8]) -> Vec<Member> {
	const LOCAL: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
	let mut out = Vec::new();
	let mut pos = 0usize;
	while pos + 30 <= data.len() {
		if data[pos..pos + 4] != LOCAL {
			break;
		}
		let Some(method) = bytes::le16(data, pos + 8) else { break };
		let Some(comp) = bytes::le32(data, pos + 18).map(|v| v as usize) else { break };
		let uncomp = bytes::le32(data, pos + 22).unwrap_or(0) as usize;
		let name_len = bytes::le16(data, pos + 26).unwrap_or(0) as usize;
		let extra_len = bytes::le16(data, pos + 28).unwrap_or(0) as usize;
		let name_start = pos + 30;
		let body = name_start + name_len + extra_len;
		if body > data.len() || body + comp > data.len() {
			break;
		}
		// Directory entries and empty files carry zero compressed bytes; they are not the
		// end of the archive.
		if comp == 0 {
			pos = body;
			continue;
		}
		let name = String::from_utf8_lossy(&data[name_start..name_start + name_len]).into_owned();
		let raw = &data[body..body + comp];
		let payload = match method {
			0 => Some(raw.to_vec()),
			8 => {
				let mut v = Vec::with_capacity(uncomp);
				flate2::read::DeflateDecoder::new(raw).read_to_end(&mut v).ok().map(|_| v)
			}
			_ => None,
		};
		if let Some(payload) = payload {
			out.push(Member { name, data: payload });
		}
		pos = body + comp;
	}
	out
}

pub fn untar(data: &[u8]) -> Vec<Member> {
	let mut out = Vec::new();
	let mut pos = 0usize;
	while pos + 512 <= data.len() {
		let header = &data[pos..pos + 512];
		if header.iter().all(|b| *b == 0) {
			break;
		}
		if &header[257..262] != b"ustar" && header[257] != 0 {
			break;
		}
		let name_end = header[..100].iter().position(|b| *b == 0).unwrap_or(100);
		let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
		let size = octal(&header[124..136]);
		let kind = header[156];
		let body = pos + 512;
		let end = body + size;
		if end > data.len() {
			break;
		}
		if matches!(kind, b'0' | 0) && size > 0 {
			out.push(Member { name, data: data[body..end].to_vec() });
		}
		pos = body + size.div_ceil(512) * 512;
	}
	out
}

fn octal(field: &[u8]) -> usize {
	field
		.iter()
		.take_while(|b| (b'0'..=b'7').contains(b))
		.fold(0usize, |acc, b| acc * 8 + (b - b'0') as usize)
}

pub fn is_tar(data: &[u8]) -> bool {
	data.len() > 262 && &data[257..262] == b"ustar"
}

pub fn is_zip(data: &[u8]) -> bool {
	data.len() > 4 && data[..4] == [0x50, 0x4b, 0x03, 0x04]
}

/// cpio "newc": 110-byte ASCII header, name and data each padded to 4 bytes. Kernels embed
/// initramfs in this form, which on some devices is the only rootfs present.
pub fn uncpio(data: &[u8]) -> Vec<Member> {
	const MAGIC: &[u8] = b"070701";
	let mut out = Vec::new();
	let mut pos = 0usize;
	while pos + 110 <= data.len() {
		if &data[pos..pos + 6] != MAGIC {
			break;
		}
		let field = |i: usize| -> usize {
			let s = &data[pos + 6 + i * 8..pos + 6 + (i + 1) * 8];
			std::str::from_utf8(s).ok().and_then(|h| usize::from_str_radix(h, 16).ok()).unwrap_or(0)
		};
		let mode = field(1);
		let size = field(6);
		let name_size = field(11);
		let name_start = pos + 110;
		if name_start + name_size > data.len() {
			break;
		}
		let name = String::from_utf8_lossy(&data[name_start..name_start + name_size])
			.trim_end_matches('\0')
			.to_string();
		if name == "TRAILER!!!" {
			break;
		}
		let body = align4(name_start + name_size);
		let end = body + size;
		if end > data.len() {
			break;
		}
		if mode & 0o170000 == 0o100000 && size > 0 {
			out.push(Member { name, data: data[body..end].to_vec() });
		}
		pos = align4(end);
	}
	out
}

fn align4(n: usize) -> usize {
	(n + 3) & !3
}
