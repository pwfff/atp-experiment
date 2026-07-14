use clap::Parser;

use atp_experiment::{recv, send};

#[derive(Debug, Parser)]
#[command(name = "atp-experiment", version, about = "RaptorQ transmission protocol demo")]
enum Cli {
    /// Send a file to a receiver.
    Send(send::SendArgs),
    /// Receive a file from a sender.
    Recv(recv::RecvArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match &cli {
        Cli::Send(args) => send::run(args).await,
        Cli::Recv(args) => recv::run(args).await,
    };
    if let Err(e) = result {
        eprintln!("atp-experiment: error: {e}");
        std::process::exit(1);
    }
}
