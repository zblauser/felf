//! LZMA1 decoder.
//!
//! squashfs-lzma blocks are raw LZMA1: a 5-byte header (props + dict_size), then a stream
//! with no end marker and no uncompressed-size field. The decode must therefore run until
//! the input is exhausted rather than until a declared length is reached — which is why
//! this exists instead of a crate.

const PROB_INIT: u16 = 1024;
const TOP: u32 = 1 << 24;
const STATES: usize = 12;
const POS_BITS_MAX: usize = 4;
const LEN_TO_POS_STATES: usize = 4;
const ALIGN_BITS: usize = 4;
const END_POS_MODEL_INDEX: usize = 14;
const FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX >> 1);
const MATCH_MIN_LEN: u32 = 2;

struct RangeDecoder<'a> {
	input: &'a [u8],
	pos: usize,
	range: u32,
	code: u32,
	exhausted: bool,
}

impl<'a> RangeDecoder<'a> {
	fn new(input: &'a [u8]) -> Self {
		let mut rc = Self { input, pos: 0, range: u32::MAX, code: 0, exhausted: false };
		rc.next_byte();
		for _ in 0..4 {
			rc.code = (rc.code << 8) | rc.next_byte() as u32;
		}
		rc
	}

	fn next_byte(&mut self) -> u8 {
		match self.input.get(self.pos) {
			Some(b) => {
				self.pos += 1;
				*b
			}
			None => {
				self.exhausted = true;
				0
			}
		}
	}

	fn normalize(&mut self) {
		if self.range < TOP {
			self.range <<= 8;
			self.code = (self.code << 8) | self.next_byte() as u32;
		}
	}

	fn bit(&mut self, probs: &mut [u16], index: usize) -> u32 {
		if index >= probs.len() {
			self.exhausted = true;
			return 0;
		}
		let p = probs[index];
		let bound = (self.range >> 11) * p as u32;
		let symbol = if self.code < bound {
			probs[index] = p + ((2048 - p) >> 5);
			self.range = bound;
			0
		} else {
			probs[index] = p - (p >> 5);
			self.code -= bound;
			self.range -= bound;
			1
		};
		self.normalize();
		symbol
	}

	fn direct_bits(&mut self, count: u32) -> u32 {
		let mut result = 0u32;
		for _ in 0..count {
			self.range >>= 1;
			self.code = self.code.wrapping_sub(self.range);
			let t = 0u32.wrapping_sub(self.code >> 31);
			self.code = self.code.wrapping_add(self.range & t);
			self.normalize();
			result = (result << 1).wrapping_add(t.wrapping_add(1));
		}
		result
	}

	fn tree(&mut self, probs: &mut [u16], bits: usize) -> u32 {
		let mut m = 1usize;
		for _ in 0..bits {
			m = (m << 1) + self.bit(probs, m) as usize;
		}
		m as u32 - (1 << bits)
	}

	fn tree_reverse(&mut self, probs: &mut [u16], bits: usize) -> u32 {
		let mut m = 1usize;
		let mut symbol = 0u32;
		for i in 0..bits {
			let b = self.bit(probs, m);
			m = (m << 1) + b as usize;
			symbol |= b << i;
		}
		symbol
	}
}

struct LenDecoder {
	choice: [u16; 2],
	low: [[u16; 8]; 16],
	mid: [[u16; 8]; 16],
	high: [u16; 256],
}

impl LenDecoder {
	fn new() -> Self {
		Self {
			choice: [PROB_INIT; 2],
			low: [[PROB_INIT; 8]; 16],
			mid: [[PROB_INIT; 8]; 16],
			high: [PROB_INIT; 256],
		}
	}

	fn decode(&mut self, rc: &mut RangeDecoder, pos_state: usize) -> u32 {
		if rc.bit(&mut self.choice, 0) == 0 {
			return rc.tree(&mut self.low[pos_state], 3);
		}
		if rc.bit(&mut self.choice, 1) == 0 {
			return 8 + rc.tree(&mut self.mid[pos_state], 3);
		}
		16 + rc.tree(&mut self.high, 8)
	}
}

fn state_literal(state: usize) -> usize {
	match state {
		0..=3 => 0,
		4..=9 => state - 3,
		_ => state - 6,
	}
}

/// LZMA_alone container: 5-byte props header, 8-byte size field, then the stream.
/// uImage payloads use this form; squashfs blocks omit the size field.
pub fn decode_alone(data: &[u8], limit: usize) -> Option<Vec<u8>> {
	if data.len() < 14 {
		return None;
	}
	let dict = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
	let declared = u64::from_le_bytes(data[5..13].try_into().ok()?);
	let cap = if declared == u64::MAX { limit } else { (declared as usize).min(limit) };
	decode(data[0], dict, &data[13..], cap)
}

/// `limit` bounds the output; decoding also stops when the input runs out, which for this
/// format is the normal termination condition rather than an error.
pub fn decode(props: u8, dict_size: u32, input: &[u8], limit: usize) -> Option<Vec<u8>> {
	if props >= 225 || input.len() < 5 {
		return None;
	}
	let lc = (props % 9) as u32;
	let rem = props / 9;
	let lp = (rem % 5) as u32;
	let pb = (rem / 5) as u32;

	let mut lit = vec![PROB_INIT; 0x300 << (lc + lp)];
	let mut is_match = [PROB_INIT; STATES << POS_BITS_MAX];
	let mut is_rep = [PROB_INIT; STATES];
	let mut is_rep_g0 = [PROB_INIT; STATES];
	let mut is_rep_g1 = [PROB_INIT; STATES];
	let mut is_rep_g2 = [PROB_INIT; STATES];
	let mut is_rep0_long = [PROB_INIT; STATES << POS_BITS_MAX];
	let mut pos_slot = [[PROB_INIT; 64]; LEN_TO_POS_STATES];
	let mut pos_decoders = [PROB_INIT; 1 + FULL_DISTANCES - END_POS_MODEL_INDEX];
	let mut align = [PROB_INIT; 1 << ALIGN_BITS];
	let mut len_dec = LenDecoder::new();
	let mut rep_len_dec = LenDecoder::new();

	let mut rc = RangeDecoder::new(input);
	let mut out: Vec<u8> = Vec::with_capacity(limit.min(1 << 20));
	let (mut state, mut rep0, mut rep1, mut rep2, mut rep3) = (0usize, 0u32, 0u32, 0u32, 0u32);
	let pos_mask = (1u32 << pb) - 1;
	let lit_pos_mask = (1u32 << lp) - 1;

	while out.len() < limit && !rc.exhausted {
		let pos_state = (out.len() as u32 & pos_mask) as usize;
		if rc.bit(&mut is_match, (state << POS_BITS_MAX) + pos_state) == 0 {
			let prev = out.last().copied().unwrap_or(0);
			let lit_state =
				(((out.len() as u32 & lit_pos_mask) << lc) + (prev as u32 >> (8 - lc))) as usize;
			let probs = &mut lit[0x300 * lit_state..0x300 * (lit_state + 1)];
			let mut symbol = 1usize;
			if state >= 7 {
				let Some(&matched) = out.get(out.len().wrapping_sub(rep0 as usize + 1)) else {
					return finish(out);
				};
				let mut matched = matched;
				while symbol < 0x100 {
					let match_bit = ((matched >> 7) & 1) as usize;
					matched <<= 1;
					let bit = rc.bit(probs, ((1 + match_bit) << 8) + symbol) as usize;
					symbol = (symbol << 1) | bit;
					if match_bit != bit {
						break;
					}
				}
			}
			while symbol < 0x100 {
				symbol = (symbol << 1) | rc.bit(probs, symbol) as usize;
			}
			out.push((symbol - 0x100) as u8);
			state = state_literal(state);
			continue;
		}

		let len;
		if rc.bit(&mut is_rep, state) != 0 {
			if out.is_empty() {
				return finish(out);
			}
			if rc.bit(&mut is_rep_g0, state) == 0 {
				if rc.bit(&mut is_rep0_long, (state << POS_BITS_MAX) + pos_state) == 0 {
					state = if state < 7 { 9 } else { 11 };
					let Some(&b) = out.get(out.len().wrapping_sub(rep0 as usize + 1)) else {
						return finish(out);
					};
					out.push(b);
					continue;
				}
			} else {
				let dist = if rc.bit(&mut is_rep_g1, state) == 0 {
					rep1
				} else {
					let d = if rc.bit(&mut is_rep_g2, state) == 0 {
						rep2
					} else {
						let t = rep3;
						rep3 = rep2;
						t
					};
					rep2 = rep1;
					d
				};
				rep1 = rep0;
				rep0 = dist;
			}
			len = rep_len_dec.decode(&mut rc, pos_state);
			state = if state < 7 { 8 } else { 11 };
		} else {
			rep3 = rep2;
			rep2 = rep1;
			rep1 = rep0;
			len = len_dec.decode(&mut rc, pos_state);
			state = if state < 7 { 7 } else { 10 };
			rep0 = decode_distance(&mut rc, &mut pos_slot, &mut pos_decoders, &mut align, len);
			if rep0 == u32::MAX || rep0 >= dict_size || rep0 as usize >= out.len() {
				return finish(out);
			}
		}

		let total = (len + MATCH_MIN_LEN) as usize;
		let start = out.len().wrapping_sub(rep0 as usize + 1);
		if start >= out.len() {
			return finish(out);
		}
		for i in 0..total {
			if out.len() >= limit {
				break;
			}
			let Some(&b) = out.get(start + i) else { break };
			out.push(b);
		}
	}
	finish(out)
}

fn finish(out: Vec<u8>) -> Option<Vec<u8>> {
	(!out.is_empty()).then_some(out)
}

fn decode_distance(
	rc: &mut RangeDecoder,
	pos_slot: &mut [[u16; 64]; LEN_TO_POS_STATES],
	pos_decoders: &mut [u16],
	align: &mut [u16],
	len: u32,
) -> u32 {
	let len_state = (len as usize).min(LEN_TO_POS_STATES - 1);
	let slot = rc.tree(&mut pos_slot[len_state], 6);
	if slot < 4 {
		return slot;
	}
	let direct = (slot >> 1) - 1;
	let mut dist = (2 | (slot & 1)) << direct;
	if (slot as usize) < END_POS_MODEL_INDEX {
		let base = dist as usize - slot as usize;
		let mut m = 1usize;
		let mut symbol = 0u32;
		for i in 0..direct {
			let b = rc.bit(pos_decoders, base + m);
			m = (m << 1) + b as usize;
			symbol |= b << i;
		}
		dist += symbol;
	} else {
		dist += rc.direct_bits(direct - ALIGN_BITS as u32) << ALIGN_BITS;
		dist += rc.tree_reverse(align, ALIGN_BITS);
	}
	dist
}
