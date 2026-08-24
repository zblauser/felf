use felf_unpack::{container, find_filesystems, FsKind};

#[test]
fn peels_trx_partitions() {
	let mut img = vec![0u8; 64];
	img[0..4].copy_from_slice(b"HDR0");
	img[16..20].copy_from_slice(&28u32.to_le_bytes());
	img[20..24].copy_from_slice(&40u32.to_le_bytes());
	let peeled = container::peel(&img);
	assert_eq!(peeled.len(), 2);
	assert!(peeled[0].note.contains("28"));
}

#[test]
fn peels_chk_then_trx() {
	let mut img = vec![0u8; 128];
	img[0..4].copy_from_slice(&0x2a23_245eu32.to_be_bytes());
	img[4..8].copy_from_slice(&58u32.to_be_bytes());
	img[58..62].copy_from_slice(b"HDR0");
	img[74..78].copy_from_slice(&28u32.to_le_bytes());
	let peeled = container::peel(&img);
	assert!(peeled.iter().any(|p| p.note.contains("TRX")));
}

#[test]
fn unwrapped_input_passes_through() {
	let peeled = container::peel(&[0u8; 16]);
	assert_eq!(peeled.len(), 1);
	assert_eq!(peeled[0].note, "no wrapper");
}

#[test]
fn finds_filesystem_signatures() {
	let mut img = vec![0u8; 512];
	img[100..104].copy_from_slice(b"hsqs");
	img[300..304].copy_from_slice(b"UBI#");
	let hits = find_filesystems(&img);
	assert_eq!(hits, vec![(100, FsKind::SquashFs), (300, FsKind::Ubi)]);
}

#[test]
fn empty_input_finds_nothing() {
	assert!(find_filesystems(&[]).is_empty());
}
