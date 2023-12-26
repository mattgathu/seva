#![deny(unused)]
use std::{env, path::PathBuf};

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod errors;
mod fs;
mod http;
mod mime;
mod server;

/// A directory http server.
/// Seva serves files from a directory, directly mapping
/// the directory structure to HTTP requests.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to server files from.
    #[arg(short, long, default_value = ".")]
    directory: String,

    /// Http port to listen on.
    #[arg(short, long, default_value = "8001")]
    port: u16,

    /// Interface to bind to.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
}

fn expand_tilde(path: &str) -> String {
    let home = match home_dir() {
        None => return path.to_string(),
        Some(home) => home.to_string_lossy().into_owned(),
    };
    path.replace('~', &home)
}

fn home_dir() -> Option<PathBuf> {
    #![allow(deprecated)]
    std::env::home_dir()
}

fn main() -> errors::Result<()> {
    let args = Args::parse();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .compact()
        .with_file(false)
        .with_line_number(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let dir = match args.directory.as_str() {
        "." => env::current_dir()?,
        _ => PathBuf::from(expand_tilde(&args.directory)),
    };

    info!("Starting seva in: {}", dir.display());
    info!(
        "Serving HTTP on {bind} port {port} (http://{bind}:{port}/) ...",
        bind = args.host,
        port = args.port,
    );

    let mut server = server::HttpServer::new(args.host, args.port, dir)?;
    server.run()?;
    Ok(())
}
