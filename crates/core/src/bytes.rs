/// Checked little/big-endian reads and byte search. Every parser here works on
/// attacker-controlled input, so these return Option rather than indexing directly.
pub fn le16(b: &[u8], off: usize) -> Option<u16> {
	b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

pub fn le32(b: &[u8], off: usize) -> Option<u32> {
	b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn le64(b: &[u8], off: usize) -> Option<u64> {
	b.get(off..off + 8)
		.map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

pub fn be32(b: &[u8], off: usize) -> Option<u32> {
	b.get(off..off + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	if needle.is_empty() || haystack.len() < needle.len() {
		return None;
	}
	haystack.windows(needle.len()).position(|w| w == needle)
}
