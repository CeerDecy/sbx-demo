//! Bounds-safe packet reads for the datapath programs.

use aya_ebpf::{EbpfContext, programs::TcContext};
use aya_ebpf_bindings::helpers::bpf_skb_load_bytes;

/// Reads exactly `dst.len()` bytes of the frame at `offset`.
///
/// [`TcContext::load_bytes`] clamps the read to the frame's remaining length,
/// which turns the size argument into a runtime value; the verifier rejects
/// that as a possibly zero-length read. Callers check `ctx.len()` first, so a
/// constant size plus this helper's own short-frame error is enough.
#[inline(always)]
pub fn load(ctx: &TcContext, offset: usize, dst: &mut [u8]) -> bool {
    // SAFETY: `ctx` is this program's `__sk_buff`, and `dst` is writable for
    // exactly the length passed alongside it.
    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.as_ptr().cast(),
            offset as u32,
            dst.as_mut_ptr().cast(),
            dst.len() as u32,
        )
    };
    ret == 0
}
