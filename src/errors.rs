use crate::base64;
use std::error::Error as StdError;
use std::{self, fmt, io};

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
    KDF,
    RNG,
    Encoding,
}

/// Error structure for the `minisign` crate.
#[derive(Debug)]
pub struct PError {
    kind: ErrorKind,
    err: Box<dyn StdError + Send + Sync>,
}

impl PError {
    pub fn exit(&self) -> ! {
        werr!("{}\n", self);
        ::std::process::exit(1)
    }

    pub fn new<E>(kind: ErrorKind, err: E) -> PError
    where
        E: Into<Box<dyn StdError + Send + Sync>>,
    {
        PError {
            kind,
            err: err.into(),
        }
    }
}

impl fmt::Display for PError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Generate => write!(f, "{}", self.err),
            ErrorKind::Sign => write!(f, "{}", self.err),
            ErrorKind::Verify => write!(f, "{}", self.err),
            ErrorKind::Misc => write!(f, "{}", self.err),
            ErrorKind::Io => write!(f, "{}", self.err),
            ErrorKind::Hash => write!(f, "{}", self.err),
            ErrorKind::KDF => write!(f, "{}", self.err),
            ErrorKind::RNG => write!(f, "{}", self.err),
            ErrorKind::Encoding => write!(f, "{}", self.err),
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
            ErrorKind::KDF => "key derivation error",
            ErrorKind::RNG => "random number generator error",
            ErrorKind::Encoding => "encoding error",
        }
    }
}

impl From<io::Error> for PError {
    fn from(err: io::Error) -> PError {
        PError::new(ErrorKind::Io, err)
    }
}

impl From<fmt::Error> for PError {
    fn from(err: fmt::Error) -> PError {
        PError::new(ErrorKind::Io, err)
    }
}

impl From<base64::Error> for PError {
    fn from(err: base64::Error) -> PError {
        PError::new(ErrorKind::Encoding, err)
    }
}

impl From<std::string::FromUtf8Error> for PError {
    fn from(err: std::string::FromUtf8Error) -> PError {
        PError::new(ErrorKind::Encoding, err)
    }
}

impl From<scrypt::errors::InvalidParams> for PError {
    fn from(err: scrypt::errors::InvalidParams) -> PError {
        PError::new(ErrorKind::KDF, err.to_string())
    }
}

impl From<scrypt::errors::InvalidOutputLen> for PError {
    fn from(err: scrypt::errors::InvalidOutputLen) -> PError {
        PError::new(ErrorKind::KDF, err.to_string())
    }
}

impl From<getrandom::Error> for PError {
    fn from(err: getrandom::Error) -> PError {
        PError::new(ErrorKind::RNG, format!("{}", err))
    }
}
