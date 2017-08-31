extern crate base64;
use std::fmt;
use std::io;
use std::error::Error as StdError;
use std;
macro_rules! werr(
    ($($arg:tt)*) => ({
        use std::io::{Write, stderr};
        write!(&mut stderr(), $($arg)*).unwrap();
    })
);

pub type Result<T> = std::result::Result<T, PError>;

#[derive(Debug)]
pub enum PError<> {
    Error,
    PasswordError(String),
    Io(io::Error),
    EncDec(base64::DecodeError),
    Generic(String),
}

impl PError {
    pub fn exit(&self) -> ! {
            werr!("{}\n", self);
            ::std::process::exit(1)
    }
}

impl fmt::Display for PError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PError::Error => f.write_str("Error!"),
            PError::PasswordError(ref err) => write!(f, "Password error: {}", err),
            PError::Generic(ref err) => write!(f, "Generic error: {}", err),
            PError::Io(ref err) => err.fmt(f),
            PError::EncDec(ref err) => err.fmt(f),
        }
    }
}
impl StdError for PError {
    fn description(&self) -> &str {
        match *self {
            PError::Error => "empty error",
            PError::Generic(_) => "generic error",
            PError::PasswordError(_)=> "password error",
            PError::Io(ref err) => err.description(),
            PError::EncDec(ref err) => err.description(),
        }
    }
}
impl From<io::Error> for PError {
    fn from(err: io::Error) -> PError {
        PError::Io(err)
    }
}
impl From<std::string::ParseError> for PError {
    fn from(_: std::string::ParseError) -> PError {
        PError::Error
    }
}

impl From<()> for PError {
    fn from(_: ()) -> PError {
        PError::Error
    }
}

impl From<base64::DecodeError> for PError {
    fn from(err: base64::DecodeError) -> PError {
        PError::EncDec(err)
    }
}