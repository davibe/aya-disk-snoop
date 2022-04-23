#![no_std]
#![no_main]


use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
    helpers::bpf_ktime_get_ns,
    helpers::bpf_probe_read,
    maps::HashMap,
    macros::map
};

use aya_log_ebpf::info;

#[repr(C)]
pub struct Request {
    // https://elixir.bootlin.com/linux/latest/source/include/linux/blk-mq.h#L77
}

#[map]
pub static mut HASH: HashMap<*const Request, u64> = HashMap::with_max_entries(1024, 0);

#[kprobe(name="aya_disk_snoop_start")]
pub fn aya_disk_snoop_start(ctx: ProbeContext) -> u32 {
    match unsafe { try_aya_disk_snoop_start(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_aya_disk_snoop_start(ctx: ProbeContext) -> Result<u32, u32> {
    let req: *const Request = ctx.arg(0).ok_or(0u32)?;
    let ts = bpf_ktime_get_ns();
    HASH.insert(&req, &ts, 0).or(Err(0u32))?;
    // info!(&ctx, "aya_disk_snoop_start size: {} {}", req as usize);
    Ok(0)
}

#[kprobe(name="aya_disk_snoop_end")]
pub fn aya_disk_snoop_end(ctx: ProbeContext) -> u32 {
    match unsafe { try_aya_disk_snoop_end(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_aya_disk_snoop_end(ctx: ProbeContext) -> Result<u32, u32> {
    let req: *const Request = ctx.arg(0).ok_or(0u32)?;
    let now = bpf_ktime_get_ns();
    let before = HASH.get(&req).ok_or(0u32)?;
    let elapsed = now - before;
    let base = req as usize;
    let cmdflags = bpf_probe_read((base + 24) as *const u32).or(Err(0u32))?;

    // off-set 40 is for linux 5.13.0
    let data_len = bpf_probe_read((base + 40) as *const u32).or(Err(0u32))?;

    info!(&ctx, "pointer: {} time: {} cmdflags: {} data-len: {}", base, elapsed / 1000000, cmdflags, data_len);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
