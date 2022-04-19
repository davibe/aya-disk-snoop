#![no_std]
#![no_main]

use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
};

#[kprobe(name="aya_disk_snoop")]
pub fn aya_disk_snoop(ctx: ProbeContext) -> u32 {
    match unsafe { try_aya_disk_snoop(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_aya_disk_snoop(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
