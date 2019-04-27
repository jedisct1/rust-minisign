extern crate base64;
extern crate clap;

use std;
use std::error::Error as StdError;
use std::fmt;
use std::io;

macro_rules! werr(
    ($($arg:tt)*) => ({
        use std::io::{Write, stderr};
        write!(&mut stderr(), $($arg)*).unwrap();
    })
);

pub type Result<T> = std::result::Result<T, PError>;

#[derive(Debug)]
pub enum ErrorKind {
    Generate,
    Sign,
    Verify,
    Io,
    Misc,
    Hash,
}

#[derive(Debug)]
pub struct PError {
    kind: ErrorKind,
    err: Box<StdError + Send + Sync>,
}

impl PError {
    pub fn exit(&self) -> ! {
        werr!("{}\n", self);
        ::std::process::exit(1)
    }
    pub fn new<E>(kind: ErrorKind, err: E) -> PError
    where
        E: Into<Box<StdError + Send + Sync>>,
    {
        PError {
            kind: kind,
            err: err.into(),
        }
    }
}

impl fmt::Display for PError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::Generate => write!(f, "{}", self.err),
            ErrorKind::Sign => write!(f, "{}", self.err),
            ErrorKind::Verify => write!(f, "{}", self.err),
            ErrorKind::Misc => write!(f, "{}", self.err),
            ErrorKind::Io => write!(f, "{}", self.err),
            ErrorKind::Hash => write!(f, "{}", self.err),
        }
    }
}
impl StdError for PError {
    fn description(&self) -> &str {
        match self.kind {
            ErrorKind::Generate => "generate error",
            ErrorKind::Sign => "sign error",
            ErrorKind::Verify => "verify error",
            ErrorKind::Misc => "misc error",
            ErrorKind::Io => "io error",
            ErrorKind::Hash => "hash error",
        }
    }
}
impl From<io::Error> for PError {
    fn from(err: io::Error) -> PError {
        PError::new(ErrorKind::Io, err)
    }
}
impl From<std::string::ParseError> for PError {
    fn from(err: std::string::ParseError) -> PError {
        PError::new(ErrorKind::Misc, err)
    }
}
impl From<clap::Error> for PError {
    fn from(err: clap::Error) -> PError {
        PError::new(ErrorKind::Misc, err)
    }
}

impl From<base64::DecodeError> for PError {
    fn from(err: base64::DecodeError) -> PError {
        PError::new(ErrorKind::Misc, err)
    }
}

impl From<std::string::FromUtf8Error> for PError {
    fn from(err: std::string::FromUtf8Error) -> PError {
        PError::new(ErrorKind::Misc, err)
    }
}
