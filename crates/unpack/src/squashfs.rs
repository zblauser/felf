use std::collections::HashMap;
use std::io::Cursor;
use std::rc::Rc;

use felf_core::bytes;

fn req<T>(v: Option<T>) -> Result<T, UnpackError> {
	v.ok_or(UnpackError::Truncated)
}

use crate::UnpackError;

const MAGIC: u32 = 0x7371_7368;
const META_MAX: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressor {
	Gzip,
	Lzma,
	Lzo,
	Xz,
	Lz4,
	Zstd,
	Unknown(u16),
}

impl Compressor {
	fn from_id(id: u16) -> Self {
		match id {
			1 => Compressor::Gzip,
			2 => Compressor::Lzma,
			3 => Compressor::Lzo,
			4 => Compressor::Xz,
			5 => Compressor::Lz4,
			6 => Compressor::Zstd,
			other => Compressor::Unknown(other),
		}
	}

	pub fn name(&self) -> String {
		match self {
			Compressor::Gzip => "gzip".into(),
			Compressor::Lzma => "lzma".into(),
			Compressor::Lzo => "lzo".into(),
			Compressor::Xz => "xz".into(),
			Compressor::Lz4 => "lz4".into(),
			Compressor::Zstd => "zstd".into(),
			Compressor::Unknown(n) => format!("unknown({n})"),
		}
	}
}

pub struct SuperBlock {
	pub inodes: u32,
	pub block_size: u32,
	pub fragments: u32,
	pub compressor: Compressor,
	pub root_ref: u64,
	pub inode_table: u64,
	pub dir_table: u64,
	pub frag_table: u64,
	pub version: (u16, u16),
}

pub struct Entry {
	pub path: String,
	pub data: Vec<u8>,
}

pub struct SquashFs<'a> {
	image: &'a [u8],
	pub sb: SuperBlock,
	meta: HashMap<u64, (Rc<Vec<u8>>, u64)>,
	frags: Option<Vec<u8>>,
	frag_cache: HashMap<u64, Rc<Vec<u8>>>,
}

fn lzma1(src: &[u8], expect: usize) -> Option<Vec<u8>> {
	if src.len() < 6 {
		return None;
	}
	let dict = bytes::le32(src, 1)?;
	crate::lzma::decode(src[0], dict, &src[5..], expect)
}

impl<'a> SquashFs<'a> {
	pub fn parse(image: &'a [u8]) -> Result<Self, UnpackError> {
		if req(bytes::le32(image, 0))? != MAGIC {
			return Err(UnpackError::NotSquashFs);
		}
		let sb = SuperBlock {
			inodes: req(bytes::le32(image, 4))?,
			block_size: req(bytes::le32(image, 12))?,
			fragments: req(bytes::le32(image, 16))?,
			compressor: Compressor::from_id(req(bytes::le16(image, 20))?),
			version: (req(bytes::le16(image, 28))?, req(bytes::le16(image, 30))?),
			root_ref: req(bytes::le64(image, 32))?,
			inode_table: req(bytes::le64(image, 64))?,
			dir_table: req(bytes::le64(image, 72))?,
			frag_table: req(bytes::le64(image, 80))?,
		};
		Ok(Self { image, sb, meta: HashMap::new(), frags: None, frag_cache: HashMap::new() })
	}

	fn inflate(&self, src: &[u8], expect: usize) -> Option<Vec<u8>> {
		match self.sb.compressor {
			Compressor::Gzip => {
				use std::io::Read;
				let mut out = Vec::with_capacity(expect);
				flate2::read::ZlibDecoder::new(src).read_to_end(&mut out).ok()?;
				Some(out)
			}
			Compressor::Xz => {
				let mut out = Vec::with_capacity(expect);
				let mut cur = Cursor::new(src);
				lzma_rs::xz_decompress(&mut cur, &mut out).ok()?;
				Some(out)
			}
			Compressor::Lzma => lzma1(src, expect),
			_ => None,
		}
	}

	fn meta_block(&mut self, pos: u64) -> (Rc<Vec<u8>>, u64) {
		if let Some(hit) = self.meta.get(&pos) {
			return hit.clone();
		}
		let p = pos as usize;
		let Some(hdr) = bytes::le16(self.image, p) else {
			return (Rc::new(Vec::new()), pos);
		};
		let size = (hdr & 0x7FFF) as usize;
		let compressed = hdr & 0x8000 == 0;
		let raw = self.image.get(p + 2..p + 2 + size).unwrap_or(&[]);
		let out = if compressed {
			self.inflate(raw, META_MAX).unwrap_or_default()
		} else {
			raw.to_vec()
		};
		let next = pos + 2 + size as u64;
		let entry = (Rc::new(out), next);
		self.meta.insert(pos, entry.clone());
		entry
	}

	fn read_meta(&mut self, start: u64, offset: usize, len: usize) -> Vec<u8> {
		let mut buf = Vec::new();
		let mut pos = start;
		while buf.len() < offset + len {
			let (blk, next) = self.meta_block(pos);
			if blk.is_empty() && next <= pos {
				break;
			}
			let empty = blk.is_empty();
			buf.extend_from_slice(&blk);
			pos = next;
			if empty {
				break;
			}
		}
		buf.get(offset..(offset + len).min(buf.len())).unwrap_or(&[]).to_vec()
	}

	fn fragment(&mut self, idx: u32) -> Option<(u64, u32)> {
		if self.frags.is_none() {
			let count = (self.sb.fragments as usize * 16).div_ceil(META_MAX);
			let mut raw = Vec::new();
			for i in 0..count {
				let ptr = bytes::le64(self.image, self.sb.frag_table as usize + i * 8)?;
				let (blk, _) = self.meta_block(ptr);
				raw.extend_from_slice(&blk);
			}
			self.frags = Some(raw);
		}
		let table = self.frags.as_ref()?;
		let base = idx as usize * 16;
		Some((bytes::le64(table, base)?, bytes::le32(table, base + 8)?))
	}

	fn inode(&mut self, reference: u64) -> Option<Inode> {
		let block = (reference >> 16) & 0xFFFF_FFFF;
		let offset = (reference & 0xFFFF) as usize;
		let base = self.sb.inode_table + block;
		let hdr = self.read_meta(base, offset, 128);
		if hdr.len() < 16 {
			return None;
		}
		let kind = bytes::le16(&hdr, 0)?;
		let mut node = Inode { kind, ..Default::default() };
		match kind {
			1 => {
				node.start = bytes::le32(&hdr, 16)? as u64;
				node.size = bytes::le16(&hdr, 24)? as u64;
				node.offset = bytes::le16(&hdr, 26)? as usize;
			}
			8 => {
				node.size = bytes::le32(&hdr, 20)? as u64;
				node.start = bytes::le32(&hdr, 24)? as u64;
				node.offset = bytes::le16(&hdr, 34)? as usize;
			}
			2 => {
				node.start = bytes::le32(&hdr, 16)? as u64;
				node.frag = bytes::le32(&hdr, 20)?;
				node.frag_offset = bytes::le32(&hdr, 24)? as usize;
				node.size = bytes::le32(&hdr, 28)? as u64;
				node.blocks = self.block_sizes(base, offset + 32, &node);
			}
			9 => {
				node.start = bytes::le64(&hdr, 16)?;
				node.size = bytes::le64(&hdr, 24)?;
				node.frag = bytes::le32(&hdr, 44)?;
				node.frag_offset = bytes::le32(&hdr, 48)? as usize;
				node.blocks = self.block_sizes(base, offset + 56, &node);
			}
			3 | 11 => {
				let len = bytes::le32(&hdr, 20)? as usize;
				let target = self.read_meta(base, offset + 24, len);
				node.symlink = Some(String::from_utf8_lossy(&target).into_owned());
			}
			_ => {}
		}
		Some(node)
	}

	fn block_sizes(&mut self, base: u64, offset: usize, node: &Inode) -> Vec<u32> {
		let bs = self.sb.block_size as u64;
		let n = if node.frag == u32::MAX {
			node.size.div_ceil(bs)
		} else {
			node.size / bs
		} as usize;
		let raw = self.read_meta(base, offset, n * 4);
		(0..n).filter_map(|i| bytes::le32(&raw, i * 4)).collect()
	}

	fn file_data(&mut self, node: &Inode) -> Vec<u8> {
		let mut out = Vec::with_capacity(node.size as usize);
		let mut pos = node.start as usize;
		let bs = self.sb.block_size as usize;
		for raw_size in &node.blocks {
			let size = (raw_size & 0x00FF_FFFF) as usize;
			if size == 0 {
				out.resize(out.len() + bs, 0);
				continue;
			}
			let chunk = self.image.get(pos..pos + size).unwrap_or(&[]).to_vec();
			pos += size;
			if raw_size & 0x0100_0000 != 0 {
				out.extend_from_slice(&chunk);
			} else if let Some(d) = self.inflate(&chunk, bs) {
				out.extend_from_slice(&d);
			}
		}
		if node.frag != u32::MAX {
			if let Some((start, raw_size)) = self.fragment(node.frag) {
				let blk = match self.frag_cache.get(&start) {
					Some(hit) => Some(Rc::clone(hit)),
					None => {
						let size = (raw_size & 0x00FF_FFFF) as usize;
						let chunk =
							self.image.get(start as usize..start as usize + size).unwrap_or(&[]).to_vec();
						let decoded = if raw_size & 0x0100_0000 != 0 {
							Some(chunk)
						} else {
							self.inflate(&chunk, bs)
						};
						decoded.map(|d| {
							let rc = Rc::new(d);
							self.frag_cache.insert(start, Rc::clone(&rc));
							rc
						})
					}
				};
				if let Some(blk) = blk {
					let want = node.size as usize - out.len().min(node.size as usize);
					let end = (node.frag_offset + want).min(blk.len());
					if node.frag_offset < end {
						out.extend_from_slice(&blk[node.frag_offset..end]);
					}
				}
			}
		}
		out.truncate(node.size as usize);
		out
	}

	fn dir_entries(&mut self, node: &Inode) -> Vec<(String, u64, u16)> {
		let mut out = Vec::new();
		if node.size <= 3 {
			return out;
		}
		let base = self.sb.dir_table + node.start;
		let data = self.read_meta(base, node.offset, node.size as usize - 3);
		let mut p = 0usize;
		while p + 12 <= data.len() {
			let Some(count) = bytes::le32(&data, p) else { break };
			let Some(start_block) = bytes::le32(&data, p + 4) else { break };
			p += 12;
			for _ in 0..=count {
				if p + 8 > data.len() {
					return out;
				}
				let Some(off) = bytes::le16(&data, p) else { return out };
				let Some(kind) = bytes::le16(&data, p + 4) else { return out };
				let Some(nsize) = bytes::le16(&data, p + 6) else { return out };
				p += 8;
				let end = (p + nsize as usize + 1).min(data.len());
				let name = String::from_utf8_lossy(&data[p..end]).into_owned();
				p = end;
				out.push((name, ((start_block as u64) << 16) | off as u64, kind));
			}
		}
		out
	}

	pub fn walk(&mut self) -> Vec<Entry> {
		let mut out = Vec::new();
		let root = self.sb.root_ref;
		self.walk_from(root, "", &mut out, 0);
		out
	}

	fn walk_from(&mut self, reference: u64, prefix: &str, out: &mut Vec<Entry>, depth: usize) {
		if depth > 64 {
			return;
		}
		let Some(node) = self.inode(reference) else { return };
		for (name, child_ref, _) in self.dir_entries(&node) {
			if name == "." || name == ".." || name.is_empty() {
				continue;
			}
			let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
			let Some(child) = self.inode(child_ref) else { continue };
			match child.kind {
				1 | 8 => self.walk_from(child_ref, &path, out, depth + 1),
				2 | 9 => {
					let data = self.file_data(&child);
					out.push(Entry { path, data });
				}
				_ => {}
			}
		}
	}
}

#[derive(Default)]
struct Inode {
	kind: u16,
	start: u64,
	size: u64,
	offset: usize,
	frag: u32,
	frag_offset: usize,
	blocks: Vec<u32>,
	symlink: Option<String>,
}
