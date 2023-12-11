#![allow(unused)]
use anyhow::Result;
use bytes::Bytes;
use bytes::{Buf, BufMut, BytesMut};
use pest::iterators::{Pair, Pairs};
use pest::Parser as PestParser;
use pest_derive::Parser as PestDeriveParser;
use seva_macros::HttpStatusCode;
use std::{fmt::Display, net::SocketAddr};
use tokio::{
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
    listener: TcpListener,
    shut_down: bool,
    handles: Vec<JoinHandle<Result<()>>>,
}

impl HttpServer {
    pub async fn new(host: String, port: u16) -> Result<HttpServer> {
        let listener = TcpListener::bind((host.clone(), port)).await?;
        let shut_down = false;
        let handles = vec![];
        Ok(Self {
            host,
            port,
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
                    let join = tokio::spawn(async move {
                        let mut handler = RequestHandler {
                            stream,
                            client_addr,
                        };
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
    fn send_header(&self, hdr: Header) -> Result<()> {
        todo!()
    }
}

struct RequestHandler {
    stream: TcpStream,
    client_addr: SocketAddr,
}
impl RequestHandler {
    async fn handle(&mut self) -> Result<()> {
        //todo
        match self._handle().await {
            Ok(_) => {
                info!("handled request");
            }
            Err(e) => {
                error!("failed to handle request. reason: {e}");
            }
        }
        Ok(())
    }

    async fn _handle(&mut self) -> Result<()> {
        let req = Request::parse(&self.read_request().await?)?;
        info!("parsed request: {req:#?}");
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
            println!("{lines:#?}");
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
                let b = self.stream.read_u8().await?;
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

    fn parse_request(buf: &str) -> Result<Request> {
        Request::parse(buf)
    }

    async fn send_error(&self, code: StatusCode, reason: &str) -> Result<()> {
        todo!()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: HttpMethod,
    pub path: String,
    pub headers: Vec<Header>,
    pub version: String,
}
impl Request {
    fn parse(req_str: &str) -> Result<Request> {
        debug!("parsing: {req_str:#?}");
        let mut res = HttpRequestParser::parse(Rule::request, req_str)?;
        let req_rule = res.next().unwrap();
        Request::try_from(req_rule)
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
            headers: vec![], // TODO
        };

        Ok(req)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Response {
    protocol: String,
    status: u16,
    status_msg: StatusCode,
    headers: Vec<Header>,
    body: Option<Body>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Body {
    // todo
}

/// HTTP defines a set of request methods to indicate the desired action to be performed for a given resource.
///
/// Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    fn new(name: impl Into<String>, value: String) -> Self {
        Self {
            name: name.into(),
            value,
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
#[derive(HttpStatusCode, Debug, Clone, PartialEq, Eq)]
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
        let req_str = "GET / HTTP/1.1\r\nHost: developer.mozilla.org\nAccept-Language: fr\r\n";
        // When
        let parsed: Request = RequestHandler::parse_request(req_str)?;
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
            version: "HTTP/1.1".to_string(),
        };
        assert_eq!(parsed, expected);
        Ok(())
    }
}
