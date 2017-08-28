extern crate base64;
use std::fmt;
use std::io;
use std::error::Error as StdError;


macro_rules! werr(
    ($($arg:tt)*) => ({
        use std::io::{Write, stderr};
        write!(&mut stderr(), $($arg)*).unwrap();
    })
);


#[derive(Debug)]
pub enum PError<> {
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
            PError::PasswordError(ref err) => write!(f, "Password error: {}", err),
            PError::Generic(ref err) => write!(f, "Unknown error: {}", err),
            PError::Io(ref err) => err.fmt(f),
            PError::EncDec(ref err) => err.fmt(f),
        }
    }
}
impl StdError for PError {
    fn description(&self) -> &str {
        match *self {
            PError::Generic(_) => "Unknown error",
            PError::PasswordError(_)=> "generic password error",
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

impl From<base64::DecodeError> for PError {
    fn from(err: base64::DecodeError) -> PError {
        PError::EncDec(err)
    }
}