#![allow(dead_code)]
#![allow(unused_imports)]

use anyhow::{anyhow, Context, Error, Result};
use bytes::Bytes;
use clap::Parser;
use h2::server::SendResponse;
use h2::RecvStream;
use handlebars::Handlebars;
use http_body_util::Empty;
use http_body_util::Full;
use hyper::body;
use hyper::body::Body;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use serde::Serialize;
use std::collections::HashMap;
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
use tokio_stream::StreamExt;
use tracing::debug;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
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
        info!("handling stream from: {peer_addr}");
        let io = TokioIo::new(socket);
        let svr = Self::build_server();
        let svc = service_fn(Self::serve_req, ctxt);
        match svr.serve_connection_with_upgrades(io, svc).await {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!(e).context("handle_stream")),
        }
    }

    async fn serve_req(
        req: Request<body::Incoming>,
        ctxt: RequestContext,
    ) -> Result<Response<Full<Bytes>>> {
        // todo
        info!("serving request: {req:?} with context: {ctxt:?}");
        let hb = Handlebars::new();
        let template = tokio::fs::read_to_string("index.html").await?;

        let dir_entries = Self::build_dir_entries(&ctxt.dir).await?;
        let mut data = HashMap::new();
        data.insert("entries".to_string(), dir_entries);
        let index = hb.render_template(&template, &data)?;

        Ok(Response::new(Full::new(Bytes::from(index))))
    }

    fn build_server() -> ServerBuilder<TokioExecutor> {
        ServerBuilder::new(TokioExecutor::new())
    }

    async fn build_dir_entries(dir: &PathBuf) -> Result<Vec<DirEntry>> {
        let mut entries = vec![];
        let mut dir_entries = tokio::fs::read_dir(dir).await?;
        while let Some(item) = dir_entries.next_entry().await? {
            let meta = item.metadata().await?;
            let entry = DirEntry {
                name: format!("{}", item.file_name().to_string_lossy()),
                icon: "rust".to_string(),
                file_type: EntryType::from(item.file_type().await?),
                ext: item.path().extension().map(|s| format!("{s:?}")),
                modified: meta.modified()?,
                created: meta.created()?,
                size: meta.len(),
            };
            entries.push(entry);
        }

        Ok(entries)
    }
}
fn service_fn<F, R, S>(f: F, ctxt: RequestContext) -> SevaSvc<F, R>
where
    F: Fn(Request<R>, RequestContext) -> S,
    S: Future,
{
    SevaSvc {
        f,
        ctxt,
        _req: PhantomData,
    }
}

#[derive(Clone)]
pub struct SevaSvc<F, R> {
    f: F,
    ctxt: RequestContext,
    _req: PhantomData<fn(R)>,
}

impl<F, ReqBody, Ret, ResBody> Service<Request<ReqBody>> for SevaSvc<F, ReqBody>
where
    F: Fn(Request<ReqBody>, RequestContext) -> Ret,
    ReqBody: Body,
    Ret: Future<Output = Result<Response<ResBody>>>,
    ResBody: Body,
{
    type Response = Response<ResBody>;
    type Error = Error;
    type Future = Ret;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        (self.f)(req, self.ctxt.clone())
    }
}

impl<F, R> fmt::Debug for SevaSvc<F, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("impl Service").finish()
    }
}

#[derive(Debug, Serialize)]
struct DirEntry {
    name: String,
    icon: String,
    file_type: EntryType,
    ext: Option<String>,
    modified: SystemTime,
    created: SystemTime,
    size: u64,
}

#[derive(Debug, Serialize)]
enum EntryType {
    File,
    Link,
    Dir,
    Other,
}
impl From<std::fs::FileType> for EntryType {
    fn from(value: std::fs::FileType) -> Self {
        if value.is_dir() {
            Self::Dir
        } else if value.is_file() {
            Self::File
        } else if value.is_symlink() {
            Self::Link
        } else {
            Self::Other
        }
    }
    //
    //
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
        "Serving HTTP on {bind} port {port} (http:://{bind}:{port}/) ...",
        bind = args.host,
        port = args.port,
    );

    let mut server = DirServer::new(args.host, args.port, dir).await?;
    server.run().await;
    Ok(())
}