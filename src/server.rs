#![allow(unused)]
use std::net::SocketAddr;

use anyhow::Result;
use seva_macros::HttpStatusCode;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

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
    fn send_error(&self, code: StatusCode, reason: &str) -> Result<()> {
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
        Ok(())
    }
    fn parse_request(&self, req_str: &str) -> Result<Request> {
        todo!()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    method: HttpMethod,
    path: String,
    headers: Vec<Header>,
    protocol: String,
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
enum HttpMethod {
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
struct Header {
    name: String,
    value: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parsing() -> Result<()> {
        // Given
        let _req_str = "GET / HTTP/1.1\nHost: developer.mozilla.org\nAccept-Language: fr";
        // When
        let parsed: Request = todo!();
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
            protocol: "HTTP/1.1".to_string(),
        };
        assert_eq!(parsed, expected);
        Ok(())
    }
}
