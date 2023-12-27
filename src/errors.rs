use core::fmt;
use std::{io, string::FromUtf8Error, time::SystemTimeError};

use thiserror::Error;

use crate::http::HttpMethod;

pub type Result<T> = std::result::Result<T, SevaError>;

#[derive(Error, Debug)]
pub enum SevaError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("request parsing failed")]
    ParsingError(#[from] ParsingError),
    #[error(transparent)]
    TimeError(#[from] SystemTimeError),
    #[error("errors that can never happen")]
    Infallible,
    #[error(transparent)]
    RenderError(#[from] handlebars::RenderError),
    #[error(transparent)]
    StringConversion(#[from] FromUtf8Error),
    #[error(transparent)]
    ShutdownError(#[from] ctrlc::Error),
    #[allow(unused)]
    #[error("Test client error: {0}")]
    TestClient(String),
    #[error("URI Too Long")]
    UriTooLong,
    #[error("Http Method not allowed: {0}")]
    MethodNotAllowed(HttpMethod),
}

#[derive(Error, Debug)]
pub enum ParsingError {
    MissingMethod,
    RequestTooLong,
    MissingVersion,
    UnknownMethod(String),
    PestRuleError(String),
    DateTime(String),
}

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{:?}", self))
    }
}

pub trait IoErrorUtils {
    fn kind(&self) -> io::ErrorKind;

    fn is_blocking(&self) -> bool {
        self.kind() == io::ErrorKind::WouldBlock
    }

    fn is_not_found(&self) -> bool {
        self.kind() == io::ErrorKind::NotFound
    }
}

impl IoErrorUtils for io::Error {
    fn kind(&self) -> io::ErrorKind {
        self.kind()
    }
}
