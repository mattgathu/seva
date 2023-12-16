#![deny(unused)]
use anyhow::Result;
use bytes::Bytes;
use chrono::{DateTime, Local};
use pest::iterators::Pair;
use pest::Parser as PestParser;
use pest_derive::Parser as PestDeriveParser;
use seva_macros::HttpStatusCode;
use std::fmt::Display;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    //TODO: use &str instead of String
    pub method: HttpMethod,
    pub path: String,
    pub headers: Vec<Header>,
    pub version: String,
    pub time: DateTime<Local>,
}

impl Request {
    pub fn parse(req_str: &str) -> Result<Request> {
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
        let req = Self {
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
pub struct Response {
    pub protocol: String,
    pub status: StatusCode,
    pub headers: Vec<Header>,
    pub body: Option<Bytes>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    // todo
}

// TODO: move all http stuff to http module
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
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}
pub enum HeaderName {
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
pub enum StatusCode {
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