use core::fmt;
use std::{io, string::FromUtf8Error, time::SystemTimeError};

use thiserror::Error;

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
