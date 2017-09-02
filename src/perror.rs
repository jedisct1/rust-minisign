extern crate base64;
extern crate clap;

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
    SignatureError(String),
    CommentError(String),
    PublicKeyError(String),
    SecretKeyError(String),
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
            PError::SignatureError(ref err) => write!(f, "Signature Error: {}", err),
            PError::CommentError(ref err) => write!(f, "Comment Error: {}", err),
            PError::PublicKeyError(ref err) => write!(f, "PublicKey Error: {}", err),
            PError::SecretKeyError(ref err) => write!(f, "SecretKey Error: {}", err),
            PError::Error => f.write_str("Error!"),
            PError::PasswordError(ref err) => write!(f, "Password Error: {}", err),
            PError::Generic(ref err) => write!(f, "Error: {}", err),
            PError::Io(ref err) => err.fmt(f),
            PError::EncDec(ref err) => err.fmt(f),
        }
    }
}
impl StdError for PError {
    fn description(&self) -> &str {
        match *self {
            PError::SignatureError(_) => "SignatureError",
            PError::CommentError(_) => "CommentError",
            PError::PublicKeyError(_) => "PublicKeyError",
            PError::SecretKeyError(_) => "SecretKeyError",
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
impl From<clap::Error> for PError {
    fn from(err: clap::Error) -> PError {
        PError::Generic(err.description().to_owned())
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