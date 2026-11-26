//! Internet checksum arithmetic (RFC 1071, RFC 1624).
//!
//! The datapath rewrites a source address and port, so the IPv4 header
//! checksum is recomputed from the header bytes and the transport checksum is
//! adjusted incrementally — a full recompute would need the payload, which
//! never enters the program.

/// Folds a 32-bit sum of 16-bit words into 16 bits, end-around carry
/// included.
///
/// Two rounds always suffice: the largest sum any caller builds is three
/// words wide (below `0x30000`), and a second fold brings the result back
/// under `0x10000`. Written without a loop because the verifier gives up on
/// long unbounded-looking jump sequences.
#[inline(always)]
fn fold(mut sum: u32) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum as u16
}

/// The header checksum of `data`, which must have an even length.
#[inline(always)]
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in data.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    !fold(sum)
}

/// Replaces the contribution of the 16-bit word `old` with `new` in a
/// previously computed `checksum`.
///
/// This is RFC 1624 equation 3, HC' = ~(~HC + ~m + m'). Both words are in
/// network byte order, as they appear on the wire.
#[inline(always)]
pub fn replace(checksum: u16, old: u16, new: u16) -> u16 {
    !fold(u32::from(!checksum) + u32::from(!old) + u32::from(new))
}
