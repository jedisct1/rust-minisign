extern crate rsign;
extern crate sodiumoxide;
extern crate libsodium_sys as ffi;
extern crate chrono;
extern crate base64;
extern crate clap;

use chrono::prelude::*;
use rsign::*;
use sodiumoxide::crypto::sign::SIGNATUREBYTES;
use std::fmt::Debug;

use std::fs::{OpenOptions, File, DirBuilder};
use std::io::{self, BufWriter, BufReader, BufRead, Read, Write};
#[cfg(not(windows))]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn create_dir<P>(path: P) -> Result<()>
    where P: AsRef<Path> + Debug
{
    DirBuilder::new()
        .recursive(true)
        .create(&path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))
        .and_then(|_| Ok(()))

}
#[cfg(windows)]
fn create_file<P: AsRef<Path> + Copy + Debug>(path: P, _mode: u32) -> Result<BufWriter<File>> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))
        .and_then(|file| Ok(BufWriter::new(file)))
}
#[cfg(not(windows))]
fn create_file<P: AsRef<Path> + Copy + Debug>(path: P, mode: u32) -> Result<BufWriter<File>> {
    OpenOptions::new()
        .mode(mode)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))
        .and_then(|file| Ok(BufWriter::new(file)))
}

fn create_sig_file<P: AsRef<Path> + Copy + Debug>(path: P) -> Result<BufWriter<File>> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))
        .and_then(|file| Ok(BufWriter::new(file)))
}

fn sk_load<P: AsRef<Path>>(sk_path: P) -> Result<SeckeyStruct> {
    let mut sk_str = OpenOptions::new()
        .read(true)
        .open(sk_path)
        .map_err(|e| PError::new(ErrorKind::Io, e))
        .and_then(|file| {
            let mut sk_buf = BufReader::new(file);
            let mut _comment = String::new();
            sk_buf.read_line(&mut _comment)?;
            let mut encoded_buf = String::new();
            sk_buf.read_line(&mut encoded_buf)?;
            base64::decode(encoded_buf.trim())
                .map_err(|e| PError::new(ErrorKind::Io, e))
                .and_then(|decoded_buf| SeckeyStruct::from(&decoded_buf[..]))

        })?;

    let pwd = get_password("Password: ")?;
    write!(io::stdout(),
           "Deriving a key from the password and decrypting the secret key... ")
            .map_err(|e| PError::new(ErrorKind::Io, e))
            .and_then(|_| {
                          io::stdout().flush()?;
                          derive_and_crypt(&mut sk_str, &pwd.as_bytes())
                      })
            .and(writeln!(io::stdout(), "done").map_err(|e| PError::new(ErrorKind::Io, e)))?;
    sk_str
        .read_checksum()
        .map_err(|e| From::from(e))
        .and_then(|checksum_vec| {
            let mut chk = [0u8; BYTES];
            chk.copy_from_slice(&checksum_vec[..]);
            if chk != sk_str.keynum_sk.chk {
                Err(PError::new(ErrorKind::Verify, "Wrong password for that key"))
            } else {
                Ok(sk_str)
            }
        })
}

fn pk_load<P: AsRef<Path>>(pk_path: P) -> Result<PubkeyStruct> {
    let pk = OpenOptions::new()
        .read(true)
        .open(pk_path)
        .map_err(|e| PError::new(ErrorKind::Io, e))
        .and_then(|file| {
            let mut pk_buf = BufReader::new(file);
            let mut _comment = String::new();
            pk_buf.read_line(&mut _comment)?;
            let mut encoded_buf = String::new();
            pk_buf.read_line(&mut encoded_buf)?;
            if encoded_buf.trim().len() != PK_B64_ENCODED_LEN {
                return Err(PError::new(ErrorKind::Io,
                                       format!("base64 conversion failed - was an actual \
                                                public key given?")));
            }
            base64::decode(encoded_buf.trim())
                .map_err(|e| {
                             PError::new(ErrorKind::Io,
                                         format!("base64 conversion failed -
                            was an actual public key given?: {}",
                                                 e))
                         })
                .and_then(|decoded_buf| PubkeyStruct::from(&decoded_buf))
        })?;
    Ok(pk)
}

fn pk_load_string(pk_string: &str) -> Result<PubkeyStruct> {
    let pk = String::from_str(pk_string)
        .map_err(|e| PError::new(ErrorKind::Io, e))
        .and_then(|encoded_string| {
            if encoded_string.trim().len() != PK_B64_ENCODED_LEN {
                return Err(PError::new(ErrorKind::Io,
                                       format!("base64 conversion failed -
                 was an actual public key given?")));
            }
            base64::decode(encoded_string.as_bytes())
                .map_err(|e| {
                             PError::new(ErrorKind::Io,
                                         format!("base64 conversion
                          failed - was an actual public key given?: {}",
                                                 e))
                         })
                .and_then(|decoded_string| PubkeyStruct::from(&decoded_string))
        })?;
    Ok(pk)
}

fn sig_load<P>(sig_file: P,
               global_sig: &mut Vec<u8>,
               trusted_comment: &mut Vec<u8>,
               hashed: &mut bool)
               -> Result<SigStruct>
    where P: AsRef<Path> + Copy + Debug
{
    File::open(sig_file)
        .map_err(|e| PError::new(ErrorKind::Io, format!("{} {:?}", e, sig_file)))
        .and_then(|file| {
            let mut buf = BufReader::new(file);
            let mut untrusted_comment = String::with_capacity(COMMENTBYTES);
            buf.read_line(&mut untrusted_comment)
                .map_err(|e| PError::new(ErrorKind::Io, e))
                .and_then(|_| {
                    let mut sig_string = String::with_capacity(SigStruct::len());
                    buf.read_line(&mut sig_string)
                        .map_err(|e| PError::new(ErrorKind::Io, e))
                        .and_then(|_| {
                            let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
                            buf.read_line(&mut t_comment)
                                .map_err(|e| PError::new(ErrorKind::Io, e))
                                .and_then(|_| {
                                    let mut g_sig = String::with_capacity(SIGNATUREBYTES);
                                    buf.read_line(&mut g_sig)
                                        .map_err(|e| PError::new(ErrorKind::Io, e))
                                        .and_then(|_| {
                                            if !untrusted_comment.starts_with(COMMENT_PREFIX) {
                                                return Err(PError::new(ErrorKind::Verify,
                                                                       format!("Untrusted comment must start with: {}", COMMENT_PREFIX)));
                                            }
                                            base64::decode(sig_string.trim().as_bytes())
                                                .map_err(|e| PError::new(ErrorKind::Io, e))
                                                .and_then(|sig_bytes| {
                                                    SigStruct::from(&sig_bytes).and_then(|sig| {
                                                        if !t_comment.starts_with(TRUSTED_COMMENT_PREFIX) {
                                                            return Err(PError::new(ErrorKind::Verify,
                                                                                   format!("trusted comment should start with: {}",
                                                                                           TRUSTED_COMMENT_PREFIX)));
                                                        }
                                                        if sig.sig_alg == SIGALG {
                                                            *hashed = false;
                                                        } else if sig.sig_alg == SIGALG_HASHED {
                                                            *hashed = true;
                                                        } else {
                                                            return Err(PError::new(ErrorKind::Verify,
                                                                                   format!("Unsupported signature algorithm")));
                                                        }
                                                        let _ = t_comment.drain(..TR_COMMENT_PREFIX_LEN).count();
                                                        trusted_comment.extend(sig.sig.iter());
                                                        trusted_comment.extend_from_slice(t_comment.trim().as_bytes());
                                                        base64::decode(g_sig.trim().as_bytes())
                                                            .map_err(|e| PError::new(ErrorKind::Io, e))
                                                            .and_then(|comm_sig| {
                                                                          global_sig.extend_from_slice(&comm_sig);
                                                                          Ok(sig)
                                                                      })
                                                    })
                                                })

                                        })
                                })
                        })
                })
        })
}

fn load_message_file<P>(message_file: P, hashed: &bool) -> Result<Vec<u8>>
    where P: AsRef<Path> + Copy + Debug
{
    if *hashed {
        return hash_message_file(message_file);
    }
    OpenOptions::new()
        .read(true)
        .open(message_file)
        .map_err(|e| PError::new(ErrorKind::Io, e))
        .and_then(|mut file| {
            if file.metadata().unwrap().len() > (1u64 << 30) {
                return Err(PError::new(ErrorKind::Io,
                                       format!("{:?} is larger than 1G try using -H",
                                               message_file)));
            }
            let mut msg_buf: Vec<u8> = Vec::new();
            file.read_to_end(&mut msg_buf)?;
            Ok(msg_buf)
        })
}

fn hash_message_file<P>(message_file: P) -> Result<Vec<u8>>
    where P: AsRef<Path> + Copy
{
    OpenOptions::new()
        .read(true)
        .open(message_file)
        .map_err(|e| PError::new(ErrorKind::Io, e))
        .and_then(|file| {
            let mut buf_reader = BufReader::new(file);
            let mut buf_chunk = [0u8; 65536];
            let state_sz = unsafe { ffi::crypto_generichash_statebytes() };
            let mut state: Vec<u8> = vec![0;state_sz];
            let ptr_state = state.as_mut_ptr() as *mut ffi::crypto_generichash_state;
            generichash::init(ptr_state).unwrap();
            while buf_reader.read(&mut buf_chunk).unwrap() > 0 {
                generichash::update(ptr_state, &buf_chunk).unwrap();
            }
            Ok(generichash::finalize(ptr_state)
                   .unwrap()
                   .as_ref()
                   .to_vec())
        })

}

fn run<'a>(args: clap::ArgMatches<'a>) -> Result<()> {

    if let Some(generate_action) = args.subcommand_matches("generate") {
        let force = generate_action.is_present("force");
        let pk_path = match generate_action.value_of("pk_path") {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(SIG_DEFAULT_PKFILE),
        };
        if pk_path.exists() {
            if !force {
                return Err(PError::new(ErrorKind::Io,
                                       format!("Key generation aborted:\n
                {:?} already exists\n
                If you really want to overwrite the existing key pair, add the -f switch to\n
                force this operation.",
                                               pk_path)));
            } else {
                try!(std::fs::remove_file(&pk_path));
            }
        }

        let sk_path = match generate_action.value_of("sk_path") {
            Some(path) => {
                let complete_path = PathBuf::from(path);
                let mut dir = complete_path.clone();
                dir.pop();
                try!(create_dir(dir));
                complete_path
            }
            None => {
                let env_path = std::env::var(SIG_DEFAULT_CONFIG_DIR_ENV_VAR);
                let path = match env_path {
                    Ok(env_path) => {
                        let mut complete_path = PathBuf::from(env_path);
                        if !complete_path.exists() {
                            return Err(PError::new(ErrorKind::Io,
                                                   format!("folder {:?} referenced by {} \
                                                            doesn't exists,
                                     \
                                                            you'll have to create yourself",
                                                           complete_path,
                                                           SIG_DEFAULT_CONFIG_DIR_ENV_VAR)));
                        }
                        complete_path.push(SIG_DEFAULT_SKFILE);
                        complete_path
                    }
                    Err(_) => {
                        let home_path =
                            std::env::home_dir().ok_or(PError::new(ErrorKind::Io,
                                                                   "can't find home dir"));
                        let mut complete_path = PathBuf::from(home_path.unwrap());
                        complete_path.push(SIG_DEFAULT_CONFIG_DIR);
                        if !complete_path.exists() {
                            try!(create_dir(&complete_path));
                        }
                        complete_path.push(SIG_DEFAULT_SKFILE);
                        complete_path
                    }
                };
                path
            }
        };

        if sk_path.exists() {
            if !force {
                return Err(PError::new(ErrorKind::Io,
                                       format!("Key generation aborted:
{:?} already exists

If you really want to overwrite the existing key pair, add the -f switch to
force this operation.",
                                               sk_path)));
            } else {
                try!(std::fs::remove_file(&sk_path));
            }
        }
        let pk_file = create_file(&pk_path, 0o644)?;
        let sk_file = create_file(&sk_path, 0o600)?;
        let (pk_str, _) = generate(pk_file, sk_file, generate_action.value_of("comment"))?;

        println!("\nThe secret key was saved as {:?} - Keep it secret!",
                 sk_path);
        println!("The public key was saved as {:?} - That one can be public.\n",
                 pk_path);
        println!("Files signed using this key pair can be verified with the following command:\n");
        println!("rsign verify <file> -P {}",
                 base64::encode(pk_str.bytes().as_slice()));

    } else if let Some(sign_action) = args.subcommand_matches("sign") {
        let sk_path = match sign_action.value_of("sk_path") {
            Some(path) => PathBuf::from(path),
            None => {
                let home_path =
                    std::env::home_dir().ok_or(PError::new(ErrorKind::Io, "can't find home dir"));
                let mut complete_path = PathBuf::from(home_path.unwrap());
                complete_path.push(SIG_DEFAULT_CONFIG_DIR);
                complete_path.push(SIG_DEFAULT_SKFILE);
                complete_path
            }
        };
        if !sk_path.exists() {
            return Err(PError::new(ErrorKind::Io,
                                   format!("can't find secret key file at {:?}, try using -s",
                                           sk_path)));
        }

        let mut pk: Option<PubkeyStruct> = None;
        if sign_action.is_present("pk_path") {
            if let Some(filename) = sign_action.value_of("pk_path") {
                pk = Some(try!(pk_load(filename)));
            }
        } else if sign_action.is_present("public_key") {
            if let Some(string) = sign_action.value_of("public_key") {
                pk = Some(try!(pk_load_string(string)));
            }
        }
        let hashed = sign_action.is_present("hash");
        let message_file = sign_action.value_of("message").unwrap(); // safe to unwrap

        let sig_file_name = if let Some(file) = sign_action.value_of("sig_file") {
            format!("{}", file)
        } else {
            format!("{}{}", message_file, SIG_SUFFIX)
        };
        let sig_buf = create_sig_file(&sig_file_name)?;

        let sk = try!(sk_load(sk_path));

        let t_comment = if let Some(trusted_comment) = sign_action.value_of("trusted-comment") {
            format!("{}", trusted_comment)
        } else {
            format!("timestamp:{}\tfile:{}",
                    Utc::now().timestamp(),
                    message_file)
        };

        let unt_comment = if let Some(untrusted_comment) =
            sign_action.value_of("untrusted-comment") {
            format!("{}{}", COMMENT_PREFIX, untrusted_comment)
        } else {
            format!("{}{}", COMMENT_PREFIX, DEFAULT_COMMENT)
        };
        let message = load_message_file(message_file, &hashed)?;

        sign(sk,
             pk,
             sig_buf,
             message.as_ref(),
             hashed,
             t_comment.as_str(),
             unt_comment.as_str())?;
    } else if let Some(verify_action) = args.subcommand_matches("verify") {

        let input = verify_action
            .value_of("pk_path")
            .or(verify_action.value_of("public_key"));

        let pk = match input {
            Some(path_or_string) => {
                if verify_action.is_present("pk_path") {
                    try!(pk_load(path_or_string))
                } else {
                    try!(pk_load_string(path_or_string))
                }
            }
            None => try!(pk_load(SIG_DEFAULT_PKFILE)),
        };

        let message_file = verify_action.value_of("file").unwrap(); //safe to unwrap

        let sig_file_name = if let Some(file) = verify_action.value_of("sig_file") {
            format!("{}", file)
        } else {
            format!("{}{}", message_file, SIG_SUFFIX)
        };
        let mut hashed: bool = false;

        let mut trusted_comment: Vec<u8> = Vec::with_capacity(TRUSTEDCOMMENTMAXBYTES);
        let mut global_sig: Vec<u8> = Vec::with_capacity(SIGNATUREBYTES);
        let sig = sig_load(sig_file_name.as_str(),
                           &mut global_sig,
                           &mut trusted_comment,
                           &mut hashed)?;

        let message = load_message_file(message_file, &hashed)?;

        verify(pk,
               sig,
               &global_sig[..],
               trusted_comment.as_ref(),
               message.as_ref(),
               verify_action.is_present("quiet"),
               verify_action.is_present("output"))?;

    } else {
        println!("{}\n", args.usage());
    }

    Ok(())
}

fn main() {
    let args = parse_args();
    run(args).map_err(|e| e.exit()).unwrap();
    std::process::exit(0);
}

#[test]
fn load_public_key_string() {
    assert!(pk_load_string("RWRzq51bKcS8oJvZ4xEm+nRvGYPdsNRD3ciFPu1YJEL8Bl/3daWaj72r").is_ok());
    assert!(pk_load_string("RWQt7oYqpar/yePp+nonossdnononovlOSkkckMMfvHuGc+0+oShmJyN5Y").is_err());
}
