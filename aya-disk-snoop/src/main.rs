use aya::{include_bytes_aligned, Bpf};
use aya::programs::KProbe;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use tokio::signal;

use aya_log::BpfLogger;

#[derive(Debug, StructOpt)]
struct Opt {
    
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::from_args();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aya-disk-snoop"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/aya-disk-snoop"
    ))?;
    BpfLogger::init(&mut bpf).unwrap();

    let program_start: &mut KProbe = bpf.program_mut("aya_disk_snoop_start").unwrap().try_into()?;
    program_start.load()?;
    program_start.attach("blk_mq_start_request", 0)?;

    let program_end: &mut KProbe = bpf.program_mut("aya_disk_snoop_end").unwrap().try_into()?;
    program_end.load()?;
    program_end.attach("blk_account_io_done", 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
