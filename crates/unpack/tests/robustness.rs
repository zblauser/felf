//! Mutation testing over every parser. These read attacker-controlled bytes: a malformed
//! image must yield a wrong answer or no answer, never a panic.
//!
//! Deterministic — a failure reports the seed that produced it.

use felf_unpack::{archive, container, find_filesystems, lzma, squashfs::SquashFs};

const LZMA_BLOCK: &[u8] = include_bytes!("fixtures/squashfs_lzma_block.bin");

struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 ^= self.0 << 13;
		self.0 ^= self.0 >> 7;
		self.0 ^= self.0 << 17;
		self.0
	}

	fn below(&mut self, n: usize) -> usize {
		if n == 0 { 0 } else { (self.next() % n as u64) as usize }
	}
}

fn mutate(seed: u64, base: &[u8]) -> Vec<u8> {
	let mut rng = Rng(seed | 1);
	let mut out = base.to_vec();
	match rng.next() % 4 {
		0 => out.truncate(rng.below(out.len().max(1))),
		1 => {
			for _ in 0..1 + rng.below(32) {
				if out.is_empty() {
					break;
				}
				let i = rng.below(out.len());
				out[i] = rng.next() as u8;
			}
		}
		2 => {
			let i = rng.below(out.len().max(1));
			out.splice(i..i, (0..rng.below(64)).map(|_| rng.next() as u8));
		}
		_ => out.iter_mut().take(rng.below(128)).for_each(|b| *b = 0xFF),
	}
	out
}

/// Counts how far mutated input actually got. A fuzz harness that never reaches the
/// parsers proves nothing, so the test asserts real work happened.
#[derive(Default)]
struct Reached {
	filesystems: usize,
	squashfs_parsed: usize,
	lzma_output: usize,
	archive_members: usize,
}

fn exercise_counted(data: &[u8], hit: &mut Reached) {
	hit.filesystems += find_filesystems(data).len();
	hit.archive_members += archive::unzip(data).len()
		+ archive::untar(data).len()
		+ archive::uncpio(data).len();
	let _ = archive::gunzip(data);
	let _ = felf_unpack::entropy(data);
	let _ = felf_unpack::encrypted_marker(data);
	for peeled in container::peel(data) {
		if let Ok(mut fs) = SquashFs::parse(&peeled.data) {
			hit.squashfs_parsed += 1;
			let _ = fs.walk();
		}
	}
	if data.len() > 6 {
		let dict = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
		if let Some(v) = lzma::decode(data[0], dict, &data[5..], 1 << 16) {
			hit.lzma_output += v.len();
		}
		let _ = lzma::decode_alone(data, 1 << 16);
	}
}

fn exercise(data: &[u8]) {
	let _ = find_filesystems(data);
	let _ = archive::unzip(data);
	let _ = archive::untar(data);
	let _ = archive::uncpio(data);
	let _ = archive::gunzip(data);
	let _ = felf_unpack::entropy(data);
	let _ = felf_unpack::encrypted_marker(data);
	for peeled in container::peel(data) {
		if let Ok(mut fs) = SquashFs::parse(&peeled.data) {
			let _ = fs.walk();
		}
	}
	if data.len() > 6 {
		let dict = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
		let _ = lzma::decode(data[0], dict, &data[5..], 1 << 16);
		let _ = lzma::decode_alone(data, 1 << 16);
	}
}

fn seeds() -> Vec<Vec<u8>> {
	let mut out = vec![LZMA_BLOCK.to_vec()];

	let mut squash = vec![0u8; 512];
	squash[0..4].copy_from_slice(b"hsqs");
	squash[12..16].copy_from_slice(&131_072u32.to_le_bytes());
	squash[20..22].copy_from_slice(&2u16.to_le_bytes());
	out.push(squash);

	let mut trx = vec![0u8; 256];
	trx[0..4].copy_from_slice(b"HDR0");
	trx[16..20].copy_from_slice(&28u32.to_le_bytes());
	out.push(trx);

	let mut chk = vec![0u8; 256];
	chk[0..4].copy_from_slice(&0x2a23_245eu32.to_be_bytes());
	chk[4..8].copy_from_slice(&58u32.to_be_bytes());
	out.push(chk);

	let mut cpio = vec![0u8; 256];
	cpio[..6].copy_from_slice(b"070701");
	cpio[6..110].fill(b'0');
	out.push(cpio);

	let mut tar = vec![0u8; 1024];
	tar[257..262].copy_from_slice(b"ustar");
	tar[124..136].copy_from_slice(b"00000000144\0");
	out.push(tar);

	let mut zip = vec![0u8; 256];
	zip[..4].copy_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
	out.push(zip);

	let mut uimage = vec![0u8; 512];
	uimage[..4].copy_from_slice(&[0x27, 0x05, 0x19, 0x56]);
	uimage[12..16].copy_from_slice(&64u32.to_be_bytes());
	uimage[31] = 3;
	out.push(uimage);

	out
}

#[test]
fn parsers_survive_mutated_input() {
	let corpus = seeds();
	let mut hit = Reached::default();
	for (i, base) in corpus.iter().enumerate() {
		for seed in 0..1500u64 {
			let data = mutate(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ i as u64, base);
			exercise_counted(&data, &mut hit);
		}
	}
	assert!(hit.filesystems > 100, "harness never matched a filesystem: {}", hit.filesystems);
	assert!(hit.squashfs_parsed > 10, "harness never parsed a squashfs: {}", hit.squashfs_parsed);
	assert!(hit.lzma_output > 10_000, "harness never decoded lzma: {}", hit.lzma_output);
	assert!(hit.archive_members > 0, "harness never read an archive member");
}

#[test]
fn parsers_survive_pathological_shapes() {
	for data in [
		vec![],
		vec![0u8; 1],
		vec![0xFFu8; 4096],
		b"hsqs".to_vec(),
		b"070701".to_vec(),
		b"HDR0".to_vec(),
		vec![0x50, 0x4b, 0x03, 0x04],
		[b"ustar".to_vec(), vec![0u8; 3]].concat(),
	] {
		exercise(&data);
	}
}
