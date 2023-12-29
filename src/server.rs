use std::{
    collections::HashMap,
    fs::{metadata, read_dir, File},
    io::{self, Cursor, Read, Seek, Write},
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
use tracing::{debug, error, info, trace, warn};

use crate::{
    errors::{IoErrorUtils, Result, SevaError},
    fs::{DirEntry, EntryType},
    http::{
        HeaderName, HttpMethod, HttpParser, Request, Response, ResponseBuilder,
        StatusCode,
    },
    mime::MimeType,
};

const MAX_URI_LEN: usize = 64000;
const HTTP_PROTOCOL: &str = "HTTP/1.0";

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
    test_mode: bool,
}

impl HttpServer {
    pub fn new(
        host: &str,
        port: u16,
        dir: PathBuf,
        test_mode: bool,
    ) -> Result<HttpServer> {
        debug!("binding to {host} on port: {port}");
        let listener = TcpListener::bind((host, port))?;
        listener.set_nonblocking(true)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let s = shutdown.clone();
        if !test_mode {
            ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))?;
        }
        Ok(Self {
            dir,
            listener,
            shutdown,
            test_mode,
        })
    }
    fn shut_down(&mut self) -> Result<()> {
        info!("kwaheri! 👋");
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            match self.listener.accept() {
                Ok((stream, client_addr)) => {
                    let dir = self.dir.clone();
                    let mut handler = RequestHandler::new(stream, client_addr, dir);
                    match handler.handle() {
                        Ok(_) => {}
                        // TODO: return 500
                        Err(e) => {
                            error!("got error while handling request: {e}")
                        }
                    }
                }
                Err(e) => {
                    // handle error
                    if !e.is_blocking() {
                        error!("failed to accept new tcp connection. Reason: {e}");
                    }
                }
            };
            if self.shutdown.load(Ordering::SeqCst) {
                self.shut_down()?;
                break;
            }
            if self.test_mode && start.elapsed() > std::time::Duration::from_secs(1)
            {
                break;
            }
        }
        Ok(())
    }
}

struct RequestHandler {
    stream: TcpStream,
    client_addr: SocketAddr,
    dir: PathBuf,
}
impl RequestHandler {
    fn new(
        stream: TcpStream,
        client_addr: SocketAddr,
        dir: PathBuf,
    ) -> RequestHandler {
        Self {
            stream,
            client_addr,
            dir,
        }
    }

    fn handle(&mut self) -> Result<()> {
        match self._handle() {
            Ok(_) => {
                trace!("RequestHandler::handle OK");
            }
            Err(e) => match e {
                SevaError::UriTooLong => {
                    self.send_error(StatusCode::UriTooLong, None)?
                }
                _ => {
                    error!("internal server error: {e}");
                    self.send_error(
                        StatusCode::InternalServerError,
                        Some(&format!("Internal Server Error. Reason: {e}")),
                    )?;
                    return Err(e);
                }
            },
        }
        Ok(())
    }

    fn _handle(&mut self) -> Result<()> {
        debug!("handling stream");
        let req_str = self.read_request()?;
        let req = Request::parse(&req_str)?;

        // check if method is allowed
        if req.method != HttpMethod::Get && req.method != HttpMethod::Head {
            let response = ResponseBuilder::method_not_allowed().build();
            self.send_response(response, &req)?;
            return Ok(());
        }

        let req_path = Self::parse_req_path(req.path)?;
        if req_path == "/" || req_path == "/index.html" || req_path.is_empty() {
            self.send_dir(&req, "/", &self.dir.clone())?;
        } else if let Some(entry) = self.lookup_path(&req_path)? {
            match entry.file_type {
                EntryType::File => {
                    if req.is_partial() {
                        self.send_partial(&req, &entry)?
                    } else {
                        self.send_file(&req, &entry)?
                    }
                }
                EntryType::Dir => {
                    if req_path.ends_with('/') {
                        trace!("RequestHandler::_handle send_dir");
                        self.send_dir(
                            &req,
                            &req_path,
                            &PathBuf::from_str(&entry.name)
                                .map_err(|_| SevaError::Infallible)?,
                        )?
                    } else {
                        trace!("RequestHandler::_handle redirect");
                        self.redirect(&req, &format!("/{}/", req_path))?
                    }
                }
            }
        } else {
            trace!("RequestHandler::_handle not found");
            let resp = ResponseBuilder::not_found().build();
            self.send_response(resp, &req)?;
        }
        Ok(())
    }

    fn send_dir(
        &mut self,
        req: &Request,
        req_path: &str,
        dir: &PathBuf,
    ) -> Result<()> {
        debug!("sending dir: {}", dir.display());
        let hb = Handlebars::new();

        let dir_entries = Self::build_dir_entries(dir)?;
        let mut data = HashMap::new();
        data.insert("entries".to_string(), dir_entries);
        let index = hb.render_template(
            &DIR_TEMPLATE.replace("rep_with_path", req_path),
            &data,
        )?;

        // TODO: data compression

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

    fn send_partial(&mut self, request: &Request, entry: &DirEntry) -> Result<()> {
        trace!("RequestHandler::send_partial");
        if let Some(val) = request.headers.get(&HeaderName::Range) {
            let ranges = HttpParser::parse_bytes_range(val)?;
            // we only serve the first range
            if let Some(range) = ranges.into_iter().next() {
                if !range.is_valid(entry.size as usize) {
                    return self.send_error(
                        StatusCode::RangeNotSatisifiable,
                        Some("invalid bytes range"),
                    );
                }
                let (start, size) = match range {
                    crate::http::BytesRange::Int {
                        first_pos,
                        last_pos,
                    } => {
                        if let Some(lpos) = last_pos {
                            let delta = lpos - first_pos;
                            (first_pos, delta)
                        } else {
                            let delta = entry.size as usize - first_pos;

                            (first_pos, delta)
                        }
                    }
                    crate::http::BytesRange::Suffix { len } => {
                        let start = entry.size as usize - len;
                        (start, len)
                    }
                };
                let mut file = File::open(&entry.name)?;
                file.seek(io::SeekFrom::Start(start as u64))?;
                let mut buf = vec![0u8; size];
                file.read_exact(&mut buf)?;
                let response = ResponseBuilder::partial()
                    .headers(self.get_file_headers(entry))
                    .header(HeaderName::ContentLength, &format!("{}", buf.len()))
                    .header(
                        HeaderName::ContentRange,
                        &format!("bytes {}-{}/{}", start, start + size, entry.size),
                    )
                    .header(HeaderName::Vary, "*")
                    .body(Cursor::new(buf))
                    .build();
                self.send_response(response, request)?;
            } else {
                warn!(
                    "RequestHandler::send_partial unreachable block: empty ranges"
                );
                self.send_error(
                    StatusCode::RangeNotSatisifiable,
                    Some("invalid Range header"),
                )?;
            };
        } else {
            error!("RequestHandler::send_partial unreachable block: missing range header value");
            self.send_error(
                StatusCode::InternalServerError,
                Some("missing range header value"),
            )?;
        }
        Ok(())
    }

    fn redirect(&mut self, req: &Request, location: &str) -> Result<()> {
        let resp = ResponseBuilder::redirect(location).build();
        self.send_response(resp, req)?;
        Ok(())
    }

    fn get_mime_type(&self, ext: Option<&String>) -> MimeType {
        debug!("mime type lookup for: {ext:?}");
        ext.and_then(|e| MimeType::from_ext(e))
            .unwrap_or(MimeType::Bin)
    }

    fn get_file_headers(&self, entry: &DirEntry) -> Vec<(HeaderName, String)> {
        let mime_type = self.get_mime_type(entry.ext.as_ref());
        vec![
            (HeaderName::ContentType, mime_type.as_str().to_owned()),
            (HeaderName::LastModified, entry.modified.to_rfc2822()),
            (HeaderName::ContentLength, format!("{}", entry.size)),
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

    fn read_request(&mut self) -> Result<String> {
        trace!("RequestHandler::read_request");
        let mut lines = vec![];
        loop {
            let mut buf = BytesMut::with_capacity(MAX_URI_LEN);
            self.read_line(&mut buf, MAX_URI_LEN)?;
            if buf.len() >= MAX_URI_LEN {
                return Err(SevaError::UriTooLong);
            }
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
        mut response: Response<T>,
        request: &Request,
    ) -> Result<()> {
        trace!("RequestHandler::send_response");
        self.send_resp_line(response.status)?;
        self.send_headers(response.headers)?;
        self.end_headers()?;

        let bytes_sent = if request.method == HttpMethod::Head {
            0
        } else {
            trace!("RequestHandler::send_response body io::copy");
            // TODO: can we do this w/o blocking
            self.stream.set_nonblocking(false)?;
            let count = io::copy(&mut response.body, &mut self.stream)? as usize;
            self.stream.set_nonblocking(true)?;
            count
        };

        self.log_response(request, response.status, bytes_sent);

        Ok(())
    }

    fn send_error(&mut self, status: StatusCode, msg: Option<&str>) -> Result<()> {
        self.send_resp_line(status)?;
        self.end_headers()?;
        if let Some(msg) = msg {
            io::copy(&mut Cursor::new(msg.as_bytes()), &mut self.stream)?;
        }

        info!(
            "{client_addr} - - [{time}] \"{req_line}\" {status} {bytes}",
            client_addr = self.client_addr,
            time = Local::now().format("%d/%b/%Y:%H:%M:%S %z"),
            req_line = "-",
            status = status.as_u16(),
            bytes = msg.map(|m| m.len()).unwrap_or(0)
        );

        Ok(())
    }

    fn send_headers(
        &mut self,
        headers: impl IntoIterator<Item = (HeaderName, impl Into<String>)>,
    ) -> Result<()> {
        for (name, val) in headers {
            self.send_hdr(name, val)?;
        }
        Ok(())
    }

    fn send_hdr(&mut self, name: HeaderName, val: impl Into<String>) -> Result<()> {
        let h = format!("{}: {}\r\n", name, val.into());
        self.stream.write_all(h.as_bytes())?;
        Ok(())
    }

    fn end_headers(&mut self) -> Result<()> {
        // Add common headers
        let server = format!("seva/{}", crate_version!());
        self.send_hdr(HeaderName::Server, server)?;
        self.send_hdr(HeaderName::Date, Local::now().to_rfc2822())?;
        self.send_hdr(HeaderName::Connection, "close")?;

        // Finish
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
            "{client_addr} - - [{time}] \"{req_line}\" {status} {bytes}",
            client_addr = self.client_addr,
            time = req.time.format("%d/%b/%Y:%H:%M:%S %z"),
            req_line = req_line,
            status = status.as_u16(),
            bytes = bytes
        )
    }

    fn send_resp_line(&mut self, status: StatusCode) -> Result<()> {
        let resp_line = format!(
            "{protocol} {status} {status_msg}\r\n",
            protocol = HTTP_PROTOCOL,
            status = status.as_u16(),
            status_msg = status,
        )
        .into_bytes();
        self.stream.write_all(&resp_line)?;
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

#[cfg(test)]
mod tests {
    use std::{
        env::current_dir,
        process::Command,
        thread::{self},
    };

    use rand::{distributions::Alphanumeric, Rng};
    use reqwest::{header::HeaderValue, redirect};
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    use super::*;

    fn get_random_port() -> u16 {
        let mut rng = rand::thread_rng();
        rng.gen_range(3000..4000)
    }

    fn get_random_string(len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    fn start_server() -> Result<u16> {
        let path = current_dir()?;
        let port = get_random_port();
        let mut server = HttpServer::new("127.0.0.1", port, path, true)?;
        thread::spawn(move || server.run());
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .compact()
            .with_file(false)
            .with_line_number(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber).ok();

        Ok(port)
    }

    #[test]
    fn shutdown_works() -> Result<()> {
        let path = current_dir()?;
        let port = get_random_port();
        let mut server = HttpServer::new("127.0.0.1", port, path, false)?;
        let shutdown = server.shutdown.clone();
        let handle = thread::spawn(move || server.run());
        shutdown.store(true, Ordering::SeqCst);
        let _ = handle.join().expect("couldn't join thread");
        Ok(())
    }

    #[test]
    fn post_method_not_allowed() -> Result<()> {
        let port = start_server()?;

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(format!("http://127.0.0.1:{port}/"))
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert_eq!(response.status().as_u16(), 405u16);

        Ok(())
    }

    #[test]
    fn root_path_ok() -> Result<()> {
        let port = start_server()?;

        let client = reqwest::blocking::Client::new();
        let response = client
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert!(response.status().is_success());
        assert_eq!(response.status().as_u16(), 200u16);

        Ok(())
    }

    #[test]
    fn missing_path_returns_404() -> Result<()> {
        let port = start_server()?;

        let client = reqwest::blocking::Client::new();
        let response = client
            .get(format!("http://127.0.0.1:{port}/x-file.json"))
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert!(response.status().is_client_error());
        assert_eq!(response.status().as_u16(), 404);

        Ok(())
    }

    #[test]
    fn redirect_on_missing_slash() -> Result<()> {
        let port = start_server()?;

        let client = reqwest::blocking::Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        let response = client
            .get(format!("http://127.0.0.1:{port}/target"))
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert!(response.status().is_redirection());
        assert!(response.headers().contains_key("location"));
        assert_eq!(response.status().as_u16(), 301);

        Ok(())
    }

    #[test]
    fn dir_serving_ok() -> Result<()> {
        let port = start_server()?;

        let client = reqwest::blocking::Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        let response = client
            .get(format!("http://127.0.0.1:{port}/target/"))
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert!(response.status().is_success());

        Ok(())
    }

    #[test]
    fn range_requests_ok() -> Result<()> {
        let port = start_server()?;

        let client = reqwest::blocking::Client::new();
        let response = client
            .get(format!("http://127.0.0.1:{port}/Cargo.toml"))
            .header("Range", "bytes=0-24")
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert!(response.status().is_success());
        assert_eq!(
            response.headers().get("content-length"),
            Some(&HeaderValue::from_str("24").unwrap())
        );
        assert_eq!(
            response.headers().get("content-type"),
            Some(&HeaderValue::from_str("application/toml").unwrap())
        );
        assert_eq!(response.status().as_u16(), 206);
        let expected_body = "[package]\nname = \"seva\"\n";
        let resp_bytes = response
            .text()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;
        assert_eq!(resp_bytes, expected_body);

        Ok(())
    }

    #[test]
    fn mime_type_works() -> Result<()> {
        let port = start_server()?;

        let client = reqwest::blocking::Client::new();
        let response = client
            .get(format!("http://127.0.0.1:{port}/Cargo.toml"))
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert!(response.status().is_success());
        assert_eq!(
            response.headers().get("content-type"),
            Some(&HeaderValue::from_str("application/toml").unwrap())
        );
        assert_eq!(response.status().as_u16(), 200);

        Ok(())
    }

    #[test]
    #[ignore = "flaky"]
    fn long_url_errors() -> Result<()> {
        let port = start_server()?;
        let s = get_random_string(65000);

        let client = reqwest::blocking::Client::new();
        let response = client
            .get(format!("http://127.0.0.1:{port}/{s}"))
            .send()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;

        assert!(response.status().is_client_error());
        assert_eq!(response.status().as_u16(), 414);

        Ok(())
    }

    #[test]
    #[ignore = "fails on ci"]
    fn main_cli_works() -> Result<()> {
        let prog_path = current_dir()?.join("target/debug/seva");
        let output = Command::new(prog_path)
            .arg("-p")
            .arg("nonsense")
            .output()
            .map_err(|e| SevaError::TestClient(format!("{}", e)))?;
        assert!(!output.status.success());
        Ok(())
    }
}
