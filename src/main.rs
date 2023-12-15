#![allow(dead_code)]
#![allow(unused_imports)]

use anyhow::{anyhow, Context, Error, Result};
use bytes::Bytes;
use clap::Parser;
use handlebars::Handlebars;
use serde::Serialize;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;
use std::{env, path::PathBuf, time::Duration};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::debug;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod fs;
mod http;
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
    #[arg(short, long, default_value = "8000")]
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

struct ServerConfig {
    keep_alive: usize,
    max_connections: usize,
    request_timeout: Duration,
}
#[derive(Debug, Clone)]
struct RequestContext {
    dir: Arc<PathBuf>,
}

struct DirServer {
    // todo
    // workers
    // configuration
    //
    listener: TcpListener,
    dir: Arc<PathBuf>,
}
impl DirServer {
    async fn new(host: String, port: u16, dir: PathBuf) -> Result<DirServer> {
        let listener = TcpListener::bind((host, port)).await?;
        Ok(DirServer {
            listener,
            dir: Arc::new(dir),
        })
    }

    async fn run(&mut self) {
        loop {
            if let Ok((sock, peer_addr)) = self.listener.accept().await {
                // spawn handler
                info!("received connection from {peer_addr}");
                let ctxt = RequestContext {
                    dir: self.dir.clone(),
                };
                tokio::spawn(async move { Self::handle_stream(sock, peer_addr, ctxt).await });
            }
        }
    }

    async fn handle_stream(
        socket: TcpStream,
        peer_addr: SocketAddr,
        ctxt: RequestContext,
    ) -> Result<()> {
        info!("handling stream from: {peer_addr} {socket:?} {ctxt:?}");
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .compact()
        .with_file(false)
        .with_line_number(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

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

    //let mut server = DirServer::new(args.host, args.port, dir).await?;
    //server.run().await;
    let mut server = server::HttpServer::new(args.host, args.port, dir).await?;
    server.run().await?;
    Ok(())
}
