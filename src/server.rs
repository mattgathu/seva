#![allow(unused)]
use anyhow::Result;
use bytes::Bytes;
use bytes::{Buf, BufMut, BytesMut};
use chrono::{DateTime, Local};
use handlebars::Handlebars;
use pest::iterators::{Pair, Pairs};
use pest::Parser as PestParser;
use pest_derive::Parser as PestDeriveParser;
use serde::Serialize;
use seva_macros::HttpStatusCode;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::format;
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
        let req_path = req.path.as_str();
        if req_path == "/" || req_path == "/index.html" {
            self.serve_index(&req).await?;
        } else if dir_map.contains_key(req_path) {
            // process entry
            todo!()
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
    async fn serve_index(&mut self, req: &Request) -> Result<()> {
        let hb = Handlebars::new();
        let template = tokio::fs::read_to_string("index.html").await?;

        let dir_entries = Self::build_dir_entries(&self.dir).await?;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: HttpMethod,
    pub path: String,
    pub headers: Vec<Header>,
    pub version: String,
    pub time: DateTime<Local>,
}
impl Request {
    fn parse(req_str: &str) -> Result<Request> {
        let mut res = HttpRequestParser::parse(Rule::request, req_str)?;
        let req_rule = res.next().unwrap();
        Request::try_from(req_rule)
    }
    fn parse_headers(pair: Pair<Rule>) -> Result<Vec<Header>> {
        let mut headers = vec![];
        for hdr in pair.into_inner() {
            let mut hdr = hdr.into_inner();
            let name = hdr.next().unwrap().as_str().to_string();
            let value = hdr.next().unwrap().as_str().to_string();
            headers.push(Header::new(name, value))
        }
        //TODO: remove clone
        headers.sort_by_key(|hdr| hdr.name.clone());

        Ok(headers)
    }
}
impl<'i> TryFrom<Pair<'i, Rule>> for Request {
    type Error = anyhow::Error;
    fn try_from(pair: Pair<'i, Rule>) -> std::prelude::v1::Result<Self, Self::Error> {
        let mut iterator = pair.into_inner();
        let mut req = Self {
            method: iterator.next().unwrap().try_into()?,
            path: iterator.next().unwrap().as_str().to_string(),
            version: iterator.next().unwrap().as_str().to_string(),
            headers: Request::parse_headers(iterator.next().unwrap())?, // TODO
            time: Local::now(),
        };

        Ok(req)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Response {
    protocol: String,
    status: StatusCode,
    headers: Vec<Header>,
    body: Option<Bytes>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Body {
    // todo
}

/// HTTP defines a set of request methods to indicate the desired action to be performed for a given resource.
///
/// Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum HttpMethod {
    /// The CONNECT method establishes a tunnel to the server identified by the target resource.
    Connect,
    /// The DELETE method deletes the specified resource.
    Delete,
    /// The GET method requests a representation of the specified resource. Requests using GET should only retrieve data.
    Get,
    /// The HEAD method asks for a response identical to a GET request, but without the response body.
    Head,
    /// The OPTIONS method describes the communication options for the target resource.
    Options,
    /// The PATCH method applies partial modifications to a resource.
    Patch,
    /// The POST method submits an entity to the specified resource, often causing a change in state or side effects on the server
    Post,
    /// The PUT method replaces all current representations of the target resource with the request payload.
    Put,
    /// The TRACE method performs a message loop-back test along the path to the target resource.
    Trace,
}
#[derive(Debug, Clone)]
pub enum HttpMethodParseError {
    UnknownMethod(String),
}
impl Display for HttpMethodParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            HttpMethodParseError::UnknownMethod(val) => {
                let s = format!("HttpMethodParseError::UnknownMethod({})", val);
                f.write_str(&s)
            }
        }
    }
}

impl<'i> TryFrom<Pair<'i, Rule>> for HttpMethod {
    type Error = HttpMethodParseError;
    fn try_from(value: Pair<'i, Rule>) -> std::prelude::v1::Result<Self, Self::Error> {
        match value.as_str() {
            "CONNECT" => Ok(HttpMethod::Connect),
            "DELETE" => Ok(HttpMethod::Delete),
            "GET" => Ok(HttpMethod::Get),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "TRACE" => Ok(HttpMethod::Trace),
            _ => Err(HttpMethodParseError::UnknownMethod(
                value.as_str().to_string(),
            )),
        }
    }
}

impl std::error::Error for HttpMethodParseError {}
impl TryFrom<&[u8]> for HttpMethod {
    type Error = HttpMethodParseError;
    fn try_from(value: &[u8]) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            b"CONNECT" => Ok(HttpMethod::Connect),
            b"DELETE" => Ok(HttpMethod::Delete),
            b"GET" => Ok(HttpMethod::Get),
            b"HEAD" => Ok(HttpMethod::Head),
            b"OPTIONS" => Ok(HttpMethod::Options),
            b"PATCH" => Ok(HttpMethod::Patch),
            b"POST" => Ok(HttpMethod::Post),
            b"PUT" => Ok(HttpMethod::Put),
            b"TRACE" => Ok(HttpMethod::Trace),
            _ => Err(HttpMethodParseError::UnknownMethod(
                String::from_utf8(value.to_vec()).unwrap_or_default(),
            )),
        }
    }
}
impl From<HttpMethod> for String {
    fn from(value: HttpMethod) -> Self {
        let s = match value {
            HttpMethod::Connect => "connect",
            HttpMethod::Delete => "delete",
            HttpMethod::Get => "get",
            HttpMethod::Head => "head",
            HttpMethod::Options => "options",
            HttpMethod::Patch => "patch",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Trace => "trace",
        };
        s.to_uppercase().to_string()
    }
}

impl Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from(*self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}
enum HeaderName {
    ContentLength,
}

impl From<HeaderName> for String {
    fn from(value: HeaderName) -> String {
        let val = match value {
            HeaderName::ContentLength => "content-length",
        };
        val.to_owned()
    }
}

/// HTTP response status codes indicate whether a specific HTTP request has been successfully completed
///
/// Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
#[derive(HttpStatusCode, Debug, Clone, PartialEq, Eq, Copy)]
enum StatusCode {
    // Informational
    /// This code is sent in response to an Upgrade request header from the client and
    /// indicates the protocol the server is switching to.
    #[code(101)]
    SwitchingProtocols,
    // Success
    /// The request succeeded.
    #[code(200)]
    Ok,
    /// There is no content to send for this request
    #[code(204)]
    NoContent,
    /// This response code is used when the Range header is sent from the client to request only part of a resource.
    #[code(206)]
    PartialContent,
    // Redirection
    /// This is used for caching purposes. It tells the client that the response has not
    /// been modified, so the client can continue to use the same cached version of the response.
    #[code(206)]
    NotModified,
    // Client Errors
    /// The server cannot or will not process the request due to something that is perceived to be
    /// a client error.
    #[code(400)]
    BadRequest,
    /// The client does not have access rights to the content; that is, it is unauthorized,
    /// so the server is refusing to give the requested resource.
    #[code(403)]
    Forbidden,
    /// The server cannot find the requested resource
    #[code(404)]
    NotFound,
    /// The request method is known by the server but is not supported by the target resource.
    #[code(405)]
    MethodNotAllowed,
    /// Request entity is larger than limits defined by server.
    #[code(413)]
    PayloadTooLarge,
    /// The URI requested by the client is longer than the server is willing to interpret.
    #[code(414)]
    UriTooLong,
    /// This response is sent on an idle connection
    #[code(408)]
    RequestTimeout,
    /// The user has sent too many requests in a given amount of time ("rate limiting").
    #[code(429)]
    TooManyRequests,
    // Server Errors
    /// The server has encountered a situation it does not know how to handle.
    #[code(500)]
    InternalServerError,
    /// The request method is not supported by the server and cannot be handled.
    #[code(501)]
    NotImplemented,
    /// The HTTP version used in the request is not supported by the server.
    #[code(505)]
    HttpVersionNotSupported,
    /// Further extensions to the request are required for the server to fulfill it.
    #[code(510)]
    NotExtended,
}

#[derive(PestDeriveParser)]
#[grammar_inline = r#"
request = { request_line ~ headers? ~ NEWLINE }

request_line = _{ method ~ " "+ ~ uri ~ " "+ ~ "HTTP/" ~ version ~ NEWLINE }
uri = { (!whitespace ~ ANY)+ }
method = { ("CONNECT" | "DELETE" | "GET" | "HEAD" | "OPTIONS" | "PATCH" | "POST" | "PUT" | "TRACE") }
version = { (ASCII_DIGIT | ".")+ }
whitespace = _{ " " | "\t" }

headers = { header+ }
header = { header_name ~ ":" ~ whitespace ~ header_value ~ NEWLINE }
header_name = { (!(NEWLINE | ":") ~ ANY)+ }
header_value = { (!NEWLINE ~ ANY)+ }
"#]
struct HttpRequestParser;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parsing() -> Result<()> {
        // Given
        let req_str =
            "GET / HTTP/1.1\r\nHost: developer.mozilla.org\r\nAccept-Language: fr\r\n\r\n";
        // When
        let parsed: Request = Request::parse(req_str)?;
        // Then
        let expected = Request {
            method: HttpMethod::Get,
            path: String::from('/'),
            headers: vec![
                Header {
                    name: "Accept-Language".to_string(),
                    value: "fr".to_string(),
                },
                Header {
                    name: "Host".to_string(),
                    value: "developer.mozilla.org".to_string(),
                },
            ],
            version: "1.1".to_string(),
            time: Local::now(),
        };
        assert_eq!(parsed.method, expected.method);
        assert_eq!(parsed.path, expected.path);
        assert_eq!(parsed.version, expected.version);
        assert_eq!(parsed.headers, expected.headers);
        Ok(())
    }
}
