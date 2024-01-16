use core::fmt;
use std::{io, num::ParseIntError, string::FromUtf8Error, time::SystemTimeError};

use thiserror::Error;

use crate::http::HeaderName;

pub type Result<T> = std::result::Result<T, SevaError>;

#[derive(Error, Debug)]
pub enum SevaError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("request parsing failed")]
    ParsingError(#[from] ParsingError),
    #[error(transparent)]
    TimeError(#[from] SystemTimeError),
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
    #[error("Missing value for header: {0}")]
    MissingHeaderValue(HeaderName),
    #[error("timed out while reading data")]
    ReadTimeOut,
    #[error("timed out while writing data")]
    WriteTimeOut,
}

#[derive(Error, Debug)]
pub enum ParsingError {
    MissingMethod,
    RequestTooLong,
    MissingVersion,
    UnknownMethod(String),
    PestRuleError(String),
    DateTime(String),
    IntError(#[from] ParseIntError),
    InvalidRangeHeader(String),
}

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{:?}", self))
    }
}

pub trait IoErrorUtils {
    fn kind(&self) -> io::ErrorKind;

    fn is_addr_in_use(&self) -> bool {
        self.kind() == io::ErrorKind::AddrInUse
    }

    fn is_blocking(&self) -> bool {
        self.kind() == io::ErrorKind::WouldBlock
    }

    fn is_timed_out(&self) -> bool {
        self.kind() == io::ErrorKind::TimedOut
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
