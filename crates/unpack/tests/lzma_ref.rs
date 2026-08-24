use felf_unpack::lzma;

const BLOCK: &[u8] = include_bytes!("fixtures/squashfs_lzma_block.bin");
const EXPECTED: &[u8] = include_bytes!("fixtures/squashfs_lzma_block.expected");

fn decode_fixture(limit: usize) -> Option<Vec<u8>> {
	let dict = u32::from_le_bytes([BLOCK[1], BLOCK[2], BLOCK[3], BLOCK[4]]);
	lzma::decode(BLOCK[0], dict, &BLOCK[5..], limit)
}

#[test]
fn matches_reference_decoder() {
	let got = decode_fixture(8192).expect("decode produced nothing");
	assert_eq!(got.len(), EXPECTED.len());
	assert_eq!(got, EXPECTED);
}

#[test]
fn honours_output_limit() {
	let got = decode_fixture(100).expect("decode produced nothing");
	assert_eq!(got.len(), 100);
	assert_eq!(&got[..], &EXPECTED[..100]);
}

#[test]
fn truncated_input_yields_partial_not_panic() {
	let dict = u32::from_le_bytes([BLOCK[1], BLOCK[2], BLOCK[3], BLOCK[4]]);
	for cut in [6usize, 32, 256, 900] {
		let got = lzma::decode(BLOCK[0], dict, &BLOCK[5..cut.min(BLOCK.len())], 8192);
		if let Some(v) = got {
			assert!(v.len() <= EXPECTED.len());
		}
	}
}

#[test]
fn rejects_invalid_props() {
	assert!(lzma::decode(255, 1 << 16, &BLOCK[5..], 8192).is_none());
}

#[test]
fn survives_garbage() {
	let garbage: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
	let _ = lzma::decode(0x5d, 1 << 20, &garbage, 8192);
}
