use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(all(target_os = "linux"))]
mod fuzzer;

#[derive(Parser)]
#[command(version, about, long_about = None, subcommand_required = true)]
struct Cli {
    /// Run for a specified time in seconds
    #[arg(short)]
    /// Replay crash
    test_time: Option<u64>,
    #[arg(short)]
    replay: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Raw mode, pass all arguments to QEMU
    #[command(external_subcommand)]
    Raw(Vec<String>),
    /// Run custom test with custom Xen image
    Run {
        xen_path: String,
        fuzzer_path: String,
    },
    /// Run VGIC fuzzer
    Vgic {},
    /// Run hypercalls fuzzer
    Hypercalls {},
}

#[cfg(target_os = "linux")]
pub fn main() -> ExitCode {
    env_logger::init();

    let cli = Cli::parse();

    if cli.replay.is_some() {
        fuzzer::replay(&cli)
    } else {
        fuzzer::fuzz(&cli)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu and libafl_qemu is only supported on linux!");
}
