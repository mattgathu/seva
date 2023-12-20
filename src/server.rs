#![allow(unused)]
use crate::{
    fs::{DirEntry, EntryType},
    http::{Header, HttpMethod, MimeType, Request, Response, StatusCode},
};
use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Local, Utc};
use handlebars::Handlebars;
use pest::{
    iterators::{Pair, Pairs},
    Parser as PestParser,
};
use pest_derive::Parser as PestDeriveParser;
use serde::Serialize;
use seva_macros::HttpStatusCode;
use std::{
    collections::HashMap,
    ffi::OsString,
    fmt::{format, Display},
    fs::{metadata, read_dir, File, Metadata},
    io::{BufReader, BufWriter, ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};
use tracing::{debug, error, info, warn};

const MAX_URI_LEN: usize = 65537;

/// An HTTP "server" is a program that accepts connections in order to service
/// HTTP requests by sending HTTP responses.
///
/// HTTP is a stateless request/response protocol for exchanging "messages"
/// across a connection.
///
/// A client sends requests to a server in the form of a "request" message with
/// a method and request target. The request might also contain header fields
/// for request modifiers, client information, and representation metadata,
/// content intended for processing in accordance with the method, and trailer
/// fields to communicate information collected while sending the content.
///
/// A server responds to a client's request by sending one or more "response"
/// messages, each including a status code. The response might also contain
/// header fields for server information, resource metadata, and representation
/// metadata, content to be interpreted in accordance with the status code, and
/// trailer fields to communicate information collected while sending the
/// content.
///
/// Ref: https://www.rfc-editor.org/rfc/rfc9110
pub struct HttpServer {
    host: String,
    port: u16,
    dir: PathBuf,
    listener: TcpListener,
    shut_down: bool,
}

impl HttpServer {
    pub fn new(host: String, port: u16, dir: PathBuf) -> Result<HttpServer> {
        let listener = TcpListener::bind((host.clone(), port))?;
        let shut_down = false;
        Ok(Self {
            host,
            port,
            dir,
            listener,
            shut_down,
        })
    }
    fn shut_down(&mut self) -> Result<()> {
        //todo
        Ok(())
    }
    pub fn run(&mut self) -> Result<()> {
        loop {
            //TODO check for shutdown signal
            match self.listener.accept() {
                Ok((stream, client_addr)) => {
                    let dir = self.dir.clone();
                    let mut handler = RequestHandler::new(stream, client_addr, dir);
                    match handler.handle() {
                        Ok(_) => {}
                        Err(e) => {
                            error!("got error while handling request: {e}")
                        }
                    }
                }
                Err(e) => {
                    // handle error
                    error!("failed to accept new tcp connection. Reason: {e}");
                }
            };
            if self.shut_down {
                self.shut_down()?;
            }
        }
        Ok(())
    }
    fn handle_stream(&mut self, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        Ok(())
    }

    fn handle_timeout(&mut self) -> Result<()> {
        todo!()
    }
}

struct RequestHandler {
    stream: TcpStream,
    client_addr: SocketAddr,
    dir: PathBuf,
    //TODO: find better place
    protocol: String,
}
impl RequestHandler {
    fn new(
        stream: TcpStream,
        client_addr: SocketAddr,
        dir: PathBuf,
    ) -> RequestHandler {
        let protocol = "HTTP/1.1".to_owned();

        RequestHandler {
            stream,
            client_addr,
            dir,
            protocol,
        }
    }
    fn handle(&mut self) -> Result<()> {
        //todo
        match self._handle() {
            Ok(_) => {
                // TODO
            }
            Err(e) => {
                error!("failed to handle request. reason: {e}");
            }
        }
        Ok(())
    }

    fn map_dir(&mut self) -> Result<HashMap<String, DirEntry>> {
        let map = Self::build_dir_entries(&self.dir)?
            .into_iter()
            .map(|e| (e.name.clone(), e))
            .collect();

        Ok(map)
    }

    fn _handle(&mut self) -> Result<()> {
        let req = Request::parse(&self.read_request()?)?;
        let dir_map = self.map_dir()?;
        let req_path = Self::parse_req_path(&req.path)?;
        if req_path == "/" || req_path == "/index.html" || req_path.is_empty() {
            self.serve_dir(&req, &self.dir.clone())?;
        } else if let Some(entry) = self.lookup_path(&req_path)? {
            // process entry
            match entry.file_type {
                EntryType::File => self.send_file(&req, &entry)?,
                EntryType::Link => self.send_file(&req, &entry)?,
                EntryType::Dir => {
                    self.serve_dir(&req, &PathBuf::from_str(&entry.name)?)?
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
            self.send_response(resp, &req)?;
        }
        self.stream.shutdown(Shutdown::Both).ok();
        Ok(())
    }
    fn serve_dir(&mut self, req: &Request, path: &PathBuf) -> Result<()> {
        debug!("serving dir: {}", path.display());
        let hb = Handlebars::new();

        let dir_entries = Self::build_dir_entries(path)?;
        let mut data = HashMap::new();
        data.insert("entries".to_string(), dir_entries);
        let index = hb.render_template(DIR_TEMPLATE, &data)?;
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

        self.send_response(resp, req)?;

        Ok(())
    }
    fn send_file(&mut self, req: &Request, entry: &DirEntry) -> Result<()> {
        let mut file = File::open(&entry.name)?;
        self.send_resp_line(StatusCode::Ok)?;
        let file_headers = self.get_file_headers(entry);
        self.send_headers(&file_headers)?;
        self.send_hdr(&Header::new("Server", "seva/0.1.0"))?;
        self.send_hdr(&Header::new("Date", Local::now().to_rfc2822()))?;
        self.send_hdr(&Header::new("Connection", "close"))?;
        self.end_headers()?;

        if req.method != HttpMethod::Head {
            std::io::copy(&mut file, &mut self.stream)?;
        }
        self.stream.shutdown(Shutdown::Both)?;

        self.log_response(req, StatusCode::Ok, entry.size as usize);
        Ok(())
    }

    fn get_mime_type(&self, ext: Option<&String>) -> MimeType {
        debug!("mime type lookup for: {ext:?}");
        ext.and_then(|e| MimeType::from_ext(e.to_string()))
            .unwrap_or(MimeType::Bin)
    }

    fn get_file_headers(&self, entry: &DirEntry) -> Vec<Header> {
        let mime_type = self.get_mime_type(entry.ext.as_ref());
        vec![
            mime_type.into(),
            Header::new("Last-Modified", entry.modified.to_rfc2822()),
            Header::new("Content-Length", format!("{}", entry.size)),
        ]
    }

    fn lookup_path(&mut self, path: &str) -> Result<Option<DirEntry>> {
        let fpath = self.dir.join(path);
        match metadata(fpath) {
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
    //TODO: optimize to be zero-copy
    fn read_request(&mut self) -> Result<String> {
        let mut lines = vec![];
        loop {
            let mut buf = BytesMut::with_capacity(MAX_URI_LEN);
            self.read_line(&mut buf, MAX_URI_LEN)?;
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
    fn read_line(&mut self, buf: &mut BytesMut, limit: usize) -> Result<()> {
        let mut sz = 0usize;
        loop {
            if sz == limit {
                break;
            } else {
                let mut b = [0u8; 1];
                self.stream.read_exact(&mut b)?;
                if b[0] as char == '\n' {
                    break;
                } else {
                    buf.put_u8(b[0]);
                }
                sz += 1;
            }
        }
        Ok(())
    }
    fn send_response(&mut self, r: Response, req: &Request) -> Result<()> {
        debug!("sending response");
        self.send_resp_line(r.status)?;
        self.send_hdr(&Header::new("Server", "seva/0.1.0"))?;
        self.send_hdr(&Header::new("Date", Local::now().to_rfc2822()))?;
        self.send_hdr(&Header::new("Connection", "close"))?;
        self.end_headers()?;
        let bytes_sent = if let Some(body) = r.body {
            self.send_body(body)?
        } else {
            0
        };
        self.stream.shutdown(Shutdown::Both)?;
        self.log_response(req, r.status, bytes_sent);

        Ok(())
    }

    fn send_body(&mut self, mut body: Bytes) -> Result<usize> {
        debug!("sending body");
        self.stream.write_all(&body)?;
        Ok(body.len())
    }

    fn send_headers(&mut self, headers: &[Header]) -> Result<()> {
        for hdr in headers {
            self.send_hdr(hdr)?;
        }
        Ok(())
    }

    fn send_hdr(&mut self, hdr: &Header) -> Result<()> {
        let h = format!("{}: {}\r\n", hdr.name, hdr.value);
        self.stream.write_all(h.as_bytes())?;
        Ok(())
    }
    fn end_headers(&mut self) -> Result<()> {
        self.stream.write_all(b"\r\n")?;
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

    fn send_resp_line(&mut self, status: StatusCode) -> Result<()> {
        let resp_line = format!(
            "{protocol} {status_code} {status_msg}\r\n",
            protocol = self.protocol,
            status_code = u16::from(status),
            status_msg = status,
        )
        .into_bytes();
        self.stream.write_all(&resp_line)?;
        Ok(())
    }

    fn send_error(&mut self, code: StatusCode, reason: &str) -> Result<()> {
        error!("{code} - {reason}");
        self.send_resp_line(code)?;
        self.stream.shutdown(Shutdown::Both)?;
        Ok(())
    }

    fn build_dir_entries(dir: &PathBuf) -> Result<Vec<DirEntry>> {
        let mut entries = vec![];
        let mut dir_entries = read_dir(dir)?;
        for entry in dir_entries {
            let item = entry?;
            let meta = item.metadata()?;
            let name = format!("{}", item.file_name().to_string_lossy());
            let entry = DirEntry::from_metadata(meta, &name)?;
            entries.push(entry);
        }
        Ok(entries)
    }
    // TODO return ref instead of owned PathBuf
    fn parse_req_path(req_path: &str) -> Result<String> {
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

const DIR_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en-us">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>Directory Listing for {{path}}</title>
<style>
html {
  font-family: sans-serif;
}
</style>
</head>
<body>
<h1>Directory Listing for {{path}}</h1>
<hr>
<ul>
{{#each entries as |e| }}
<li><a href={{name}}>{{name}}</a></li>
{{/each}}
</ul>
<hr>
</body>
</html>
"#;
