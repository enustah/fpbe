mod common;

use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

use common::tp::tp_load_and_attach_prog;

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/fpbe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/fpbe"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // just for test
    tp_load_and_attach_prog(&mut bpf, "enter_open_at", "syscalls", "sys_enter_openat")?;
    tp_load_and_attach_prog(&mut bpf, "enter_execve", "syscalls", "sys_enter_execve")?;

    // tp sys_write
    tp_load_and_attach_prog(&mut bpf, "sys_enter_write", "syscalls", "sys_enter_write")?;
    tp_load_and_attach_prog(&mut bpf, "sys_exit_write", "syscalls", "sys_exit_write")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
