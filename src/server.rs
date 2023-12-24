use std::{
    collections::HashMap,
    fs::{metadata, read_dir, File},
    io::{self, Cursor, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use bytes::{BufMut, BytesMut};
use chrono::Local;
use clap::crate_version;
use handlebars::Handlebars;
use tracing::{debug, error, info, trace};

use crate::{
    errors::{IoErrorUtils, Result, SevaError},
    fs::{DirEntry, EntryType},
    http::{
        Header, HeaderName, HttpMethod, MimeType, Request, Response,
        ResponseBuilder, StatusCode,
    },
};

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
    dir: PathBuf,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
}

impl HttpServer {
    pub fn new(host: String, port: u16, dir: PathBuf) -> Result<HttpServer> {
        debug!("binding to {host} on port: {port}");
        let listener = TcpListener::bind((host.clone(), port))?;
        listener.set_nonblocking(true)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let s = shutdown.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))?;
        Ok(Self {
            dir,
            listener,
            shutdown,
        })
    }
    fn shut_down(&mut self) -> Result<()> {
        info!("kwaheri!");
        Ok(())
    }
    pub fn run(&mut self) -> Result<()> {
        loop {
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
                    if e.is_blocking() {
                        error!("failed to accept new tcp connection. Reason: {e}");
                    }
                }
            };
            if self.shutdown.load(Ordering::SeqCst) {
                self.shut_down()?;
                break;
            }
        }
        Ok(())
    }

    //fn handle_timeout(&mut self) -> Result<()> { todo!() }
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
        let protocol = "HTTP/1.0".to_owned();

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

    fn _handle(&mut self) -> Result<()> {
        debug!("handling stream");
        let req_str = self.read_request()?;
        let req = Request::parse(&req_str)?;
        let req_path = Self::parse_req_path(req.path)?;
        if req_path == "/" || req_path == "/index.html" || req_path.is_empty() {
            self.send_index(&req, "/", &self.dir.clone())?;
        } else if let Some(entry) = self.lookup_path(&req_path)? {
            match entry.file_type {
                EntryType::File => self.send_file(&req, &entry)?,
                EntryType::Dir => {
                    if req_path.ends_with('/') {
                        self.send_index(
                            &req,
                            &req_path,
                            &PathBuf::from_str(&entry.name)
                                .map_err(|_| SevaError::Infallible)?,
                        )?
                    } else {
                        self.redirect(&req, &format!("/{}/", req_path))?
                    }
                }
            }
        } else {
            // return 404
            let resp = ResponseBuilder::not_found().build();
            self.send_response(resp, &req)?;
        }
        Ok(())
    }
    fn send_index(
        &mut self,
        req: &Request,
        req_path: &str,
        dir: &PathBuf,
    ) -> Result<()> {
        debug!("serving dir: {}", dir.display());
        let hb = Handlebars::new();

        let dir_entries = Self::build_dir_entries(dir)?;
        let mut data = HashMap::new();
        data.insert("entries".to_string(), dir_entries);
        let index = hb.render_template(
            &DIR_TEMPLATE.replace("rep_with_path", req_path),
            &data,
        )?;

        let resp = ResponseBuilder::ok()
            .body(Cursor::new(index.into_bytes()))
            .build();
        self.send_response(resp, req)?;

        Ok(())
    }

    fn send_file(&mut self, req: &Request, entry: &DirEntry) -> Result<()> {
        let resp = ResponseBuilder::ok()
            .headers(self.get_file_headers(entry))
            .body(File::open(&entry.name)?)
            .build();
        self.send_response(resp, req)?;

        Ok(())
    }

    fn redirect(&mut self, req: &Request, location: &str) -> Result<()> {
        let resp = ResponseBuilder::redirect(location).build();
        self.send_response(resp, req)?;
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
            Header::new(HeaderName::LastModified, entry.modified.to_rfc2822()),
            Header::new(HeaderName::ContentLength, format!("{}", entry.size)),
        ]
    }

    fn lookup_path(&mut self, path: &str) -> Result<Option<DirEntry>> {
        debug!("path lookup: {path}");
        let fpath = self.dir.join(path);
        debug!("path lookup fpath: {fpath:?}");
        match metadata(fpath) {
            Ok(meta) => Ok(Some(DirEntry::from_metadata(meta, path)?)),
            Err(e) => {
                if e.is_not_found() {
                    Ok(None)
                } else {
                    Err(SevaError::Io(e))
                }
            }
        }
    }
    //TODO: optimize to be zero-copy
    fn read_request(&mut self) -> Result<String> {
        debug!("reading request");
        let mut lines = vec![];
        loop {
            let mut buf = BytesMut::with_capacity(MAX_URI_LEN);
            self.read_line(&mut buf, MAX_URI_LEN)?;
            let s = String::from_utf8(buf.to_vec())?;
            let len = s.len();
            trace!("req line: {s}");
            lines.push(s);
            if len == 1 {
                break;
            }
        }
        let mut res = String::new();
        for line in lines {
            res.push_str(&format!("{}\n", line))
        }
        debug!("read request");
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
                //TODO: possible to get stuck infinitely
                // fix by adding timeout
                loop {
                    match self.stream.read_exact(&mut b) {
                        Ok(_) => break,
                        Err(e) if e.is_blocking() => continue,
                        Err(e) => return Err(SevaError::Io(e)),
                    }
                }
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
    fn send_response<T: Read>(
        &mut self,
        mut r: Response<T>,
        req: &Request,
    ) -> Result<()> {
        debug!("sending response");
        self.send_resp_line(r.status)?;
        let server = format!("seva/{}", crate_version!());
        self.send_hdr(&Header::new(HeaderName::Server, server))?;
        self.send_hdr(&Header::new(HeaderName::Date, Local::now().to_rfc2822()))?;
        self.send_hdr(&Header::new(HeaderName::Connection, "close"))?;
        self.send_headers(&r.headers)?;
        self.end_headers()?;
        let bytes_sent = if req.method == HttpMethod::Head {
            0
        } else {
            debug!("sending body");
            io::copy(&mut r.body, &mut self.stream)? as usize
        };
        self.log_response(req, r.status, bytes_sent);

        Ok(())
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

    #[allow(unused)]
    fn send_error(&mut self, code: StatusCode, reason: &str) -> Result<()> {
        error!("{code} - {reason}");
        self.send_resp_line(code)?;
        Ok(())
    }

    fn build_dir_entries(dir: &PathBuf) -> Result<Vec<DirEntry>> {
        let mut entries = vec![];
        let dir_entries = read_dir(dir)?;
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
        debug!("parsing request path: {req_path:?}");
        let mut req_path = req_path;
        if let Some((l, _)) = req_path.split_once('?') {
            req_path = l;
        }
        if let Some((l, _)) = req_path.split_once('#') {
            req_path = l;
        }
        let ends_with_slash = req_path.ends_with('/');
        let mut parts = vec![];
        for frag in req_path.split('/') {
            if frag.is_empty() {
                continue;
            } else if frag == ".." {
                parts.pop();
            } else {
                parts.push(frag);
            }
        }
        let mut path: String = parts.join("/");
        if ends_with_slash {
            path.push('/');
        }

        Ok(path)
    }
}

const DIR_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en-us">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>Directory Listing</title>
<style>
html {
  font-family: sans-serif;
}
</style>
</head>
<body>
<h1>Directory Listing for rep_with_path</h1>
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
