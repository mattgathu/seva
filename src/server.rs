#![allow(unused)]
use crate::fs::{DirEntry, EntryType};
use crate::http::{Header, HttpMethod, Response, StatusCode};
use crate::http::{MimeType, Request};
use anyhow::Result;
use bytes::Bytes;
use bytes::{Buf, BufMut, BytesMut};
use chrono::{DateTime, Local, Utc};
use handlebars::Handlebars;
use pest::iterators::{Pair, Pairs};
use pest::Parser as PestParser;
use pest_derive::Parser as PestDeriveParser;
use serde::Serialize;
use seva_macros::HttpStatusCode;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::format;
use std::fs::Metadata;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;
use std::{fmt::Display, net::SocketAddr};
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::{
    fs::read_dir,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

const MAX_URI_LEN: usize = 65537;

/// An HTTP "server" is a program that accepts connections in order to service HTTP requests by sending HTTP responses.
///
/// HTTP is a stateless request/response protocol for exchanging "messages" across a connection.
///
/// A client sends requests to a server in the form of a "request" message with a method and request target.
/// The request might also contain header fields for request modifiers, client information,
/// and representation metadata, content intended for processing in accordance with the method,
/// and trailer fields to communicate information collected while sending the content.
///
/// A server responds to a client's request by sending one or more "response" messages,
/// each including a status code. The response might also contain header fields for server information,
/// resource metadata, and representation metadata, content to be interpreted in accordance with the
/// status code, and trailer fields to communicate information collected while sending the content.
///
/// Ref: https://www.rfc-editor.org/rfc/rfc9110
pub struct HttpServer {
    host: String,
    port: u16,
    dir: PathBuf,
    listener: TcpListener,
    shut_down: bool,
    handles: Vec<JoinHandle<Result<()>>>,
}

impl HttpServer {
    pub async fn new(host: String, port: u16, dir: PathBuf) -> Result<HttpServer> {
        let listener = TcpListener::bind((host.clone(), port)).await?;
        let shut_down = false;
        let handles = vec![];
        Ok(Self {
            host,
            port,
            dir,
            listener,
            shut_down,
            handles,
        })
    }
    fn shut_down(&mut self) -> Result<()> {
        //todo
        Ok(())
    }
    pub async fn run(&mut self) -> Result<()> {
        //todo
        // 1. check for new conn
        // 2. spawn task to handle new conn
        // 3. repeat
        loop {
            match self.listener.accept().await {
                Ok((stream, client_addr)) => {
                    // handle conn
                    let dir = self.dir.clone();
                    let join = tokio::spawn(async move {
                        let mut handler = RequestHandler::new(stream, client_addr, dir);
                        handler.handle().await
                    });
                    self.handles.push(join);
                }
                Err(e) => {
                    // handle error
                    error!("failed to accept new tcp connection. Reason: {e}");
                }
            }
            if self.shut_down {
                self.shut_down()?;
            }
        }
        Ok(())
    }
    async fn handle_stream(&mut self, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        Ok(())
    }

    fn handle_timeout(&mut self) -> Result<()> {
        todo!()
    }
}

struct RequestHandler {
    reader: BufReader<OwnedReadHalf>,
    writer: BufWriter<OwnedWriteHalf>,
    client_addr: SocketAddr,
    dir: PathBuf,
    //TODO: find better place
    protocol: String,
}
impl RequestHandler {
    fn new(stream: TcpStream, client_addr: SocketAddr, dir: PathBuf) -> RequestHandler {
        let (rdr, wrt) = stream.into_split();
        let reader = BufReader::new(rdr);
        let writer = BufWriter::new(wrt);
        let protocol = "HTTP/1.1".to_owned();

        RequestHandler {
            reader,
            writer,
            client_addr,
            dir,
            protocol,
        }
    }
    async fn handle(&mut self) -> Result<()> {
        //todo
        match self._handle().await {
            Ok(_) => {
                // TODO
            }
            Err(e) => {
                error!("failed to handle request. reason: {e}");
            }
        }
        Ok(())
    }

    async fn map_dir(&mut self) -> Result<HashMap<String, DirEntry>> {
        let map = Self::build_dir_entries(&self.dir)
            .await?
            .into_iter()
            .map(|e| (e.name.clone(), e))
            .collect();

        Ok(map)
    }

    async fn _handle(&mut self) -> Result<()> {
        let req = Request::parse(&self.read_request().await?)?;
        let dir_map = self.map_dir().await?;
        let req_path = Self::parse_req_path(&req.path).await?;
        if req_path == "/" || req_path == "/index.html" || req_path.is_empty() {
            self.serve_dir(&req, &self.dir.clone()).await?;
        } else if let Some(entry) = self.lookup_path(&req_path).await? {
            // process entry
            match entry.file_type {
                EntryType::File => self.send_file(&req, &entry).await?,
                EntryType::Link => {
                    //TODO
                }
                EntryType::Dir => {
                    self.serve_dir(&req, &PathBuf::from_str(&entry.name)?)
                        .await?
                }
                EntryType::Other => {
                    //TODO
                }
            }
        } else {
            // return 404
            let resp = Response {
                protocol: self.protocol.clone(),
                status: StatusCode::NotFound,
                headers: vec![],
                body: None,
            };
            self.send_response(resp, &req).await?;
        }
        Ok(())
    }
    async fn serve_dir(&mut self, req: &Request, path: &PathBuf) -> Result<()> {
        let hb = Handlebars::new();
        let template = tokio::fs::read_to_string("index.html").await?;

        let dir_entries = Self::build_dir_entries(path).await?;
        let mut data = HashMap::new();
        data.insert("entries".to_string(), dir_entries);
        let index = hb.render_template(&template, &data)?;
        let body = if req.method == HttpMethod::Head {
            None
        } else {
            Some(Bytes::from(index))
        };

        let resp = Response {
            protocol: self.protocol.clone(),
            status: StatusCode::Ok,
            headers: vec![],
            body,
        };

        self.send_response(resp, req).await?;

        Ok(())
    }
    async fn send_file(&mut self, req: &Request, entry: &DirEntry) -> Result<()> {
        let mime_type = self.get_mime_type(entry.ext.as_ref());
        let mut file = tokio::fs::File::open(&entry.name).await?;
        self.send_resp_line(StatusCode::Ok).await?;
        self.send_header(&Header::new("Server", "seva/0.1.0"))
            .await?;
        self.send_header(&mime_type.into()).await?;
        self.send_header(&Header::new("Date", Local::now().to_rfc2822()))
            .await?;
        self.send_header(&Header::new("Last-Modified", entry.modified.to_rfc2822()))
            .await?;
        self.send_header(&Header::new("Content-Length", format!("{}", entry.size)))
            .await?;
        self.send_header(&Header::new("Connection", "close"))
            .await?;
        self.end_headers().await?;

        if req.method != HttpMethod::Head {
            tokio::io::copy(&mut file, &mut self.writer).await?;
        }
        self.writer.shutdown().await?;

        self.log_response(req, StatusCode::Ok, entry.size as usize);
        Ok(())
    }

    fn get_mime_type(&self, ext: Option<&String>) -> MimeType {
        debug!("mime type lookup for: {ext:?}");
        ext.and_then(|e| MimeType::from_ext(e.to_string()))
            .unwrap_or(MimeType::Bin)
    }

    async fn lookup_path(&mut self, path: &str) -> Result<Option<DirEntry>> {
        let fpath = self.dir.join(path);
        match tokio::fs::metadata(fpath).await {
            Ok(meta) => Ok(Some(DirEntry::from_metadata(meta, path)?)),
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(e))
                }
            }
        }
    }
    async fn read_request(&mut self) -> Result<String> {
        let mut lines = vec![];
        loop {
            let mut buf = BytesMut::with_capacity(MAX_URI_LEN);
            self.read_line(&mut buf, MAX_URI_LEN).await?;
            let s = String::from_utf8(buf.to_vec())?;
            let len = s.len();
            lines.push(s);
            if len == 1 {
                break;
            }
        }
        let mut res = String::new();
        for line in lines {
            res.push_str(&format!("{}\n", line))
        }
        Ok(res)
    }

    //TODO: optimize
    async fn read_line(&mut self, buf: &mut BytesMut, limit: usize) -> Result<()> {
        let mut sz = 0usize;
        loop {
            if sz == limit {
                break;
            } else {
                let b = self.reader.read_u8().await?;
                if b as char == '\n' {
                    break;
                } else {
                    buf.put_u8(b);
                }
                sz += 1;
            }
        }
        Ok(())
    }
    async fn send_response(&mut self, r: Response, req: &Request) -> Result<()> {
        self.send_resp_line(r.status).await?;
        self.send_header(&Header::new("Server", "seva/0.1.0"))
            .await?;
        self.send_header(&Header::new("Date", Local::now().to_rfc2822()))
            .await?;
        self.send_header(&Header::new("Connection", "close"))
            .await?;
        self.end_headers().await?;
        let bytes_sent = if let Some(body) = r.body {
            self.send_body(body).await?
        } else {
            0
        };
        self.writer.shutdown().await?;
        self.log_response(req, r.status, bytes_sent);

        Ok(())
    }

    async fn send_body(&mut self, mut body: impl Buf) -> Result<usize> {
        let mut sz = 0;
        while body.has_remaining() {
            self.writer.write_u8(body.get_u8()).await?;
            sz += 1;
        }
        Ok(sz)
    }

    async fn send_header(&mut self, hdr: &Header) -> Result<()> {
        let h = format!("{}: {}\r\n", hdr.name, hdr.value);
        self.writer.write_all(h.as_bytes()).await?;
        Ok(())
    }
    async fn end_headers(&mut self) -> Result<()> {
        self.writer.write_all(b"\r\n").await?;
        Ok(())
    }
    /// Log the request using the common log format
    ///
    /// [Log formats for HTTP Server](https://www.ibm.com/docs/en/i/7.5?topic=logging-log-formats)
    fn log_response(&self, req: &Request, status: StatusCode, bytes: usize) {
        let req_line = format!(
            "{method} {path} HTTP/{version}",
            method = req.method,
            path = req.path,
            version = req.version
        );
        info!(
            "{client_addr} - - [{time}] \"{req_line}\" {status_code} {bytes}",
            client_addr = self.client_addr,
            time = req.time.format("%d/%b/%Y:%H:%M:%S %z"),
            req_line = req_line,
            status_code = u16::from(status),
            bytes = bytes
        )
    }

    async fn send_resp_line(&mut self, status: StatusCode) -> Result<()> {
        let resp_line = format!(
            "{protocol} {status_code} {status_msg}\r\n",
            protocol = self.protocol,
            status_code = u16::from(status),
            status_msg = status,
        )
        .into_bytes();
        self.writer.write_all(&resp_line).await?;
        Ok(())
    }

    async fn send_error(&mut self, code: StatusCode, reason: &str) -> Result<()> {
        error!("{code} - {reason}");
        self.send_resp_line(code).await?;
        self.writer.shutdown().await?;
        Ok(())
    }

    async fn build_dir_entries(dir: &PathBuf) -> Result<Vec<DirEntry>> {
        let mut entries = vec![];
        let mut dir_entries = tokio::fs::read_dir(dir).await?;
        while let Some(item) = dir_entries.next_entry().await? {
            let meta = item.metadata().await?;
            let name = format!("{}", item.file_name().to_string_lossy());
            let entry = DirEntry::from_metadata(meta, &name)?;
            entries.push(entry);
        }
        Ok(entries)
    }
    // TODO return ref instead of owned PathBuf
    async fn parse_req_path(req_path: &str) -> Result<String> {
        let mut req_path = req_path;
        if let Some((l, _)) = req_path.split_once('?') {
            req_path = l;
        }
        if let Some((l, _)) = req_path.split_once('#') {
            req_path = l;
        }
        let path: String = req_path.split('/').filter(|p| !p.is_empty()).collect();

        Ok(path)
    }
}
