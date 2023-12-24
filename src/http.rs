#![deny(unused)]
use std::{
    fmt::Display,
    io::{self, Empty, Read},
};

use crate::mime::MimeType;
use chrono::{DateTime, Local};
use pest::{iterators::Pair, Parser as PestParser};
use pest_derive::Parser as PestDeriveParser;
use tracing::warn;

use crate::errors::{ParsingError, Result, SevaError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    //TODO: use &str instead of String
    pub method: HttpMethod,
    pub path: &'a str,
    pub headers: Vec<Header>,
    pub version: &'a str,
    pub time: DateTime<Local>,
}

impl<'a> Request<'a> {
    pub fn parse(req_str: &str) -> Result<Request> {
        let mut res = HttpRequestParser::parse(Rule::request, req_str)
            .map_err(|e| ParsingError::PestRuleError(format!("{e:?}")))?;
        let req_rule = res.next().unwrap();
        Request::try_from(req_rule)
    }

    fn parse_headers(pair: Pair<Rule>) -> Result<Vec<Header>> {
        let mut headers = vec![];
        for hdr in pair.into_inner() {
            let mut hdr = hdr.into_inner();
            let hdr_name_opt = hdr.next().unwrap().as_str();
            if let Some(name) =
                HeaderName::from_str(hdr_name_opt.to_lowercase().as_str())
            {
                let value = hdr.next().unwrap().as_str().to_string();
                headers.push(Header::new(name, value))
            } else {
                warn!("unknown header: {hdr_name_opt}")
            }
        }
        headers.sort();

        Ok(headers)
    }
}
impl<'i> TryFrom<Pair<'i, Rule>> for Request<'i> {
    //TODO: use concrete error
    type Error = SevaError;
    fn try_from(
        pair: Pair<'i, Rule>,
    ) -> std::prelude::v1::Result<Self, Self::Error> {
        let mut iterator = pair.into_inner();
        let method = iterator.next().unwrap().try_into()?;
        let path = iterator.next().unwrap().as_str();
        let version = iterator.next().unwrap().as_str();
        let headers = match iterator.next() {
            Some(rule) => Request::parse_headers(rule)?,
            None => vec![],
        };
        let req = Self {
            method,
            path,
            version,
            headers, // TODO
            time: Local::now(),
        };

        Ok(req)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<B>
where
    B: Read,
{
    pub status: StatusCode,
    pub headers: Vec<Header>,
    pub body: B,
}
impl<B> Response<B>
where
    B: Read,
{
    pub fn new(status: StatusCode, headers: Vec<Header>, body: B) -> Response<B> {
        Self {
            status,
            headers,
            body,
        }
    }
}

pub struct ResponseBuilder<B> {
    status: StatusCode,
    headers: Vec<Header>,
    body: B,
}

impl ResponseBuilder<Empty> {
    fn new(status: StatusCode, headers: Vec<Header>) -> ResponseBuilder<Empty> {
        Self {
            status,
            headers,
            body: io::empty(),
        }
    }

    pub fn ok() -> ResponseBuilder<Empty> {
        Self::new(StatusCode::Ok, vec![])
    }

    pub fn not_found() -> ResponseBuilder<Empty> {
        Self::new(StatusCode::NotFound, vec![])
    }

    pub fn redirect(location: &str) -> ResponseBuilder<Empty> {
        Self::new(
            StatusCode::MovedPermanently,
            vec![Header::new(HeaderName::Location, location)],
        )
    }
    pub fn body<B: Read>(&self, body: B) -> ResponseBuilder<B> {
        ResponseBuilder {
            status: self.status,
            headers: self.headers.clone(),
            body,
        }
    }
}
#[allow(unused)]
impl<B> ResponseBuilder<B>
where
    B: Read,
{
    pub fn header(&mut self, hdr: Header) -> &mut Self {
        self.headers.push(hdr);
        self
    }

    pub fn headers(&mut self, hdrs: Vec<Header>) -> &mut Self {
        self.headers.extend(hdrs);
        self
    }

    pub fn status(&mut self, status: StatusCode) -> &mut Self {
        self.status = status;
        self
    }

    pub fn build(self) -> Response<B> {
        Response::new(self.status, self.headers, self.body)
    }
}

/// HTTP defines a set of request methods to indicate the desired action to be
/// performed for a given resource.
///
/// Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum HttpMethod {
    /// The CONNECT method establishes a tunnel to the server identified by the
    /// target resource.
    Connect,
    /// The DELETE method deletes the specified resource.
    Delete,
    /// The GET method requests a representation of the specified resource.
    /// Requests using GET should only retrieve data.
    Get,
    /// The HEAD method asks for a response identical to a GET request, but
    /// without the response body.
    Head,
    /// The OPTIONS method describes the communication options for the target
    /// resource.
    Options,
    /// The PATCH method applies partial modifications to a resource.
    Patch,
    /// The POST method submits an entity to the specified resource, often
    /// causing a change in state or side effects on the server
    Post,
    /// The PUT method replaces all current representations of the target
    /// resource with the request payload.
    Put,
    /// The TRACE method performs a message loop-back test along the path to the
    /// target resource.
    Trace,
}

impl<'i> TryFrom<Pair<'i, Rule>> for HttpMethod {
    type Error = ParsingError;
    fn try_from(
        value: Pair<'i, Rule>,
    ) -> std::prelude::v1::Result<Self, Self::Error> {
        Self::try_from(value.as_str().as_bytes())
    }
}

impl TryFrom<&[u8]> for HttpMethod {
    type Error = ParsingError;
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
            _ => Err(ParsingError::UnknownMethod(
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
//TODO: turn into enum
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Header {
    pub name: HeaderName,
    pub value: String,
}

impl Header {
    pub fn new(name: HeaderName, value: impl Into<String>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }
}

impl From<MimeType> for Header {
    fn from(val: MimeType) -> Header {
        Header {
            name: HeaderName::ContentType,
            value: val.to_string(),
        }
    }
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

macro_rules! status_codes {
    (
        $(
            $(#[$docs:meta])+
            ($name:ident, $code:literal);
        )+
    ) => {
        /// HTTP response status codes indicate whether a specific HTTP request has been
        /// successfully completed
        ///
        /// Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
        #[allow(unused)]
        pub enum StatusCode {
             $(
                $(#[$docs])*
                $name,
            )+
        }

        impl StatusCode {
            pub fn as_u16(&self) -> u16 {

                match *self {
                    $(
                        StatusCode::$name => $code,
                    )+
                }
            }
        }

        impl std::fmt::Display for StatusCode {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.as_u16())
            }
        }

    };
}

status_codes! {

    /// This code is sent in response to an Upgrade request header from the
    /// client and indicates the protocol the server is switching to.
    (SwitchingProtocols,101);

    /// The request succeeded.
    (Ok, 200);

    /// There is no content to send for this request
    (NoContent,204);

    /// This response code is used when the Range header is sent from the client
    /// to request only part of a resource.
    (PartialContent,206);

    /// This redirect status response code indicates that the requested resource
    /// has been definitively moved to the URL given by the Location headers.
    (MovedPermanently,301);

    /// This is used for caching purposes. It tells the client that the response
    /// has not been modified, so the client can continue to use the same
    /// cached version of the response.
    (NotModified,304);

    /// The server cannot or will not process the request due to something that
    /// is perceived to be a client error.
    (BadRequest,400);

    /// The client does not have access rights to the content; that is, it is
    /// unauthorized, so the server is refusing to give the requested
    /// resource.
    (Forbidden,403);

    /// The server cannot find the requested resource
    (NotFound,404);

    /// The request method is known by the server but is not supported by the
    /// target resource.
    (MethodNotAllowed,405);

    /// Request entity is larger than limits defined by server.
    (PayloadTooLarge,413);

    /// The URI requested by the client is longer than the server is willing to
    /// interpret.
    (UriTooLong, 414);

    /// This response is sent on an idle connection
    (RequestTimeout,408);

    /// The user has sent too many requests in a given amount of time ("rate
    /// limiting").
    (TooManyRequests,429);

    /// The server has encountered a situation it does not know how to handle.
    (InternalServerError,500);

    /// The request method is not supported by the server and cannot be handled.
    (NotImplemented, 501);

    /// The HTTP version used in the request is not supported by the server.
    (HttpVersionNotSupported, 505);

    /// Further extensions to the request are required for the server to fulfill it.
    (NotExtended,510);
}

macro_rules! header_names {
    (
        $(
            $(#[$docs:meta])+
            ($hname:ident, $name_str:literal);
        )+
    ) => {

        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        pub enum HeaderName {
            $(
                $(#[$docs])*
                $hname,
            )+
        }
        impl HeaderName {
            pub fn as_str(&self) -> &str {
                match *self {
                    $(
                        HeaderName::$hname => $name_str,
                    )+
                }
            }

            pub fn from_str(s: &str) -> Option<HeaderName> {
                match s {
                    $(
                        $name_str => Some(HeaderName::$hname),
                    )+
                    _ => None
                }
            }
        }
        impl std::fmt::Display for HeaderName {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

    };
}

// inspired by the standard_headers! macro in the http crate
header_names! {
    /// Advertises which content types the client is able to understand.
    (Accept, "accept");

    /// Advertises which content encoding the client is able to understand.
    (AcceptEncoding, "accept-encoding");

    /// Advertises which languages the client is able to understand.
    (AcceptLanguage, "accept-language");


    /// Marker used by the server to advertise partial request support.
    (AcceptRanges, "accept-ranges");

    /// Lists the set of methods support by a resource.
    (Allow, "allow");

    /// Specifies directives for caching mechanisms in both requests and
    /// responses.
    (CacheControl, "cache-control");

    /// Controls whether or not the network connection stays open after the
    /// current transaction finishes.
    (Connection, "connection");

    /// Indicates if the content is expected to be displayed inline.
    (ContentDisposition, "content-disposition");

    /// Used to compress the media-type.
    (ContentEncoding, "content-encoding");

    /// Indicates the size of the entity-body.
    (ContentLength, "content-length");

    /// Used to indicate the media type of the resource.
    (ContentType, "content-type");

    /// Contains the date and time at which the message was originated.
    (Date, "date");

    /// Specifies the domain name of the server and (optionally) the TCP port
    /// number on which the server is listening.
    (Host, "host");

    /// Makes a request conditional based on the modification date.
    (IfModifiedSince, "if-modified-since");

    /// Makes the request conditional based on the last modification date.
    (IfUnmodifiedSince, "if-unmodified-since");

    /// Content-Types that are acceptable for the response.
    (LastModified, "last-modified");

    /// Indicates the URL to redirect a page to.
    (Location, "location");

    /// Indicates the part of a document that the server should return.
    (Range, "range");

    /// Contains information about the software used by the origin server to
    /// handle the request.
    (Server, "server");

    /// Contains a string that allows identifying the requesting client's
    /// software.
    (UserAgent, "user-agent");

    /// General HTTP header contains information about possible problems with
    /// the status of the message.
    (Warning, "warning");
}

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
            path: "/",
            headers: vec![
                Header {
                    name: HeaderName::AcceptLanguage,
                    value: "fr".to_string(),
                },
                Header {
                    name: HeaderName::Host,
                    value: "developer.mozilla.org".to_string(),
                },
            ],
            version: "1.1",
            time: Local::now(),
        };
        assert_eq!(parsed.method, expected.method);
        assert_eq!(parsed.path, expected.path);
        assert_eq!(parsed.version, expected.version);
        assert_eq!(parsed.headers, expected.headers);
        Ok(())
    }
}
