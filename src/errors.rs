use core::fmt;
use std::{io, time::SystemTimeError};

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SevaError>;

#[derive(Error, Debug)]
pub enum SevaError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("request parsing failed")]
    ParsingError(#[from] ParsingError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error(transparent)]
    TimeError(#[from] SystemTimeError),
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
