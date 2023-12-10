#![allow(unused)]
use anyhow::Result;
use bytes::Bytes;
use bytes::{Buf, BufMut, BytesMut};
use nom::bytes::complete::tag;
use nom::bytes::complete::take_while1;
use nom::character::is_alphabetic as is_alpha;
use nom::sequence::preceded;
use nom::sequence::Tuple;
use nom::AsChar;
use nom::IResult;
use nom::Parser;
use seva_macros::HttpStatusCode;
use std::{fmt::Display, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

const MAX_URI_LEN: usize = 65537;

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
        let mut buf = BytesMut::with_capacity(MAX_URI_LEN);
        self.read_line(&mut buf, MAX_URI_LEN).await?;
        if buf.len() == MAX_URI_LEN {
            self.send_error(StatusCode::UriTooLong, "Request URI Too Long")
                .await?;
        } else {
            let req = Self::parse_request(&buf)?;
            info!("parsed request: {req:#?}");
        }
        Ok(())
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

    fn parse_request(buf: &[u8]) -> Result<Request> {
        let (
            _i,
            TempReq {
                method,
                version,
                path,
            },
        ) = Self::parse_bytes(buf).map_err(|_| anyhow::format_err!("Request parsing failed."))?;

        let method = HttpMethod::try_from(method)?;
        let version = String::from_utf8(version.to_vec())?;
        let path = String::from_utf8(path.to_vec())?;

        Ok(Request {
            method,
            path,
            version,
            headers: vec![],
        })
    }

    fn parse_bytes(i: &[u8]) -> IResult<&[u8], TempReq> {
        let method = take_while1(is_alpha);
        let space = take_while1(|c| c == b' ');
        let space2 = take_while1(|c| c == b' ');
        let path = take_while1(|c| c != b' ');
        let is_version = |c: u8| c.is_ascii_digit() || c == b'.';
        let http = tag("HTTP/");
        let version = take_while1(is_version);
        let line_ending = tag("\r");

        let http_version = preceded(http, version);

        let (input, (method, _, path, _, version, _)) =
            (method, space, path, space2, http_version, line_ending).parse(i)?;

        Ok((
            input,
            TempReq {
                method,
                version,
                path,
            },
        ))
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
                String::from_utf8(value.to_vec()).unwrap(),
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
struct TempReq<'a> {
    method: &'a [u8],
    version: &'a [u8],
    path: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parsing() -> Result<()> {
        // Given
        let req_str = "GET / HTTP/1.1\nHost: developer.mozilla.org\nAccept-Language: fr";
        // When
        let buf = BytesMut::from(req_str);
        let parsed: Request = RequestHandler::parse_request(&buf)?;
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
