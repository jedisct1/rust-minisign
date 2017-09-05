extern crate rsign;
extern crate sodiumoxide;
extern crate base64;
extern crate libsodium_sys as ffi;
extern crate rpassword;
extern crate chrono;
extern crate clap;

use rsign::*;

use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey, Signature, SIGNATUREBYTES,
                                SECRETKEYBYTES};
use sodiumoxide::crypto::pwhash::{self, MemLimit, OpsLimit};
use chrono::prelude::*;

use std::fmt::Display;
use std::io::{self, BufWriter, BufReader, BufRead, Read, Write};
use std::fs::{self, OpenOptions, File, DirBuilder};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use std::str::FromStr;

use std::fmt::Debug;


macro_rules! fatal {
    ($($tt:tt)*) => {{
        use std::io::Write;
        writeln!(&mut ::std::io::stderr(), $($tt)*).unwrap();
        ::std::process::exit(1)
    }}
}

fn create_dir<P>(path: P) -> Result<()> 
where P: AsRef<Path> + Copy + Debug
{
    DirBuilder::new()
        .mode(0o777)
        .create(&path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("{}: {:?}",e, path )))
        .and_then(|_| Ok(()))       
      
}

fn create_file_rw<P: AsRef<Path> + Copy + Debug >(path: P, mode: u32) -> Result<BufWriter<File>> {
    OpenOptions::new()
        .mode(mode)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("{}: {:?}", e, path )))
        .and_then(|file| Ok(BufWriter::new(file)))
}
fn create_sig_file<P: AsRef<Path> + Copy + Debug>(path: P) -> Result<BufWriter<File>> {
    OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)
            .map_err(|e| PError::new(ErrorKind::Io, format!("{}: {:?}", e, path )))
            .and_then(|file| Ok(BufWriter::new(file)))
}

fn get_password(prompt: &str) -> Result<String> {
    let pwd = rpassword::prompt_password_stdout(prompt)?;
    if pwd.len() == 0 {
        Err(PError::new(ErrorKind::Misc, "passphrase can't be blank"))
    } else if pwd.len() > PASSWORDMAXBYTES {
        Err(PError::new(ErrorKind::Misc, "passphrase can't exceed 1024 bytes lenght"))
    } else {
        Ok(pwd)
    }
}

fn derive_and_crypt(sk_str: &mut SeckeyStruct, pwd: &[u8]) -> Result<()> {
    let mut stream = [0u8; BYTES + SECRETKEYBYTES + KEYNUMBYTES];
    pwhash::Salt::from_slice(&sk_str.kdf_salt)
        .ok_or(PError::new(ErrorKind::Misc, "failed to generate Salt from random bytes" ))
        .and_then(|salt| {

            pwhash::derive_key(&mut stream,
                               &pwd,
                               &salt,
                               OpsLimit(load_usize_le(&sk_str.kdf_opslimit_le)),
                               MemLimit(load_usize_le(&sk_str.kdf_memlimit_le)))
                    .map_err(|_| PError::new(ErrorKind::Misc, "failed to derive key from password" ))

        })?;
    sk_str.xor_keynum(&stream);
    Ok(())
}


fn generate_keys<P>(path_pk: P, path_sk: P, comment: Option<&str>, force: bool) -> Result<()>
    where P: AsRef<Path> + Copy + Display + Debug
{

    if path_sk.as_ref().exists() {
        if force {
            fs::remove_dir_all(path_sk)?;
        } else {
            return Err(PError::new(ErrorKind::Generate, format!("sorry, you have a secret key named: {} \ntry using --force if you want to overwrite", path_sk)));
        }
    }
    
    let mut path_sk = path_sk.as_ref().to_path_buf();
    
    create_dir(&path_sk)?;
    
    path_sk.push(SIG_DEFAULT_SKFILE);
    //let path_pk = path_pk.as_ref().canonicalize().unwrap();
    if path_pk.as_ref().exists() {
        if force {
            fs::remove_file(path_pk)?;
        } else {
            return Err(PError::new(ErrorKind::Generate, format!("sorry, you have a public key named: {} \ntry using --force if you want to overwrite", path_pk)));
        }
    }

    let (pk_str, mut sk_str) = gen_keystruct();
    sk_str
        .checksum()
        .map_err(|_| PError::new(ErrorKind::Generate, "failed to hash and write checksum!"))?;
    write!(io::stdout(), "Please enter a password to protect the secret key.\n")?;
    let pwd = get_password("Password: ")?;
    let pwd2 = get_password("Password (one more time): ")?;
    if pwd != pwd2 {
        return Err(PError::new(ErrorKind::Generate, "passwords don't match!"));
    }

    write!(io::stdout(), "Deriving a key from password... ")
        .map_err(|e| PError::new(ErrorKind::Io, e))
        .and_then(|_| {
                      io::stdout().flush()?;
                      derive_and_crypt(&mut sk_str, &pwd.as_bytes())
                  })
        .and(writeln!(io::stdout(), "Done!").map_err(|e| PError::new(ErrorKind::Io, e)))?;

    let mut pk_buf = create_file_rw(path_pk, 0o644)?;
    write!(pk_buf, "{}rsign public key: ", rsign::COMMENT_PREFIX)?;
    writeln!(pk_buf,
             "{:X}",
             rsign::load_usize_le(&pk_str.keynum_pk.keynum[..]))?;
    writeln!(pk_buf, "{}", base64::encode(&pk_str.bytes()))?;
    pk_buf.flush()?;

    let mut sk_buf = create_file_rw(&path_sk, 0o600)?;
    write!(sk_buf, "{}", rsign::COMMENT_PREFIX)?;
    if let Some(comment) = comment {
        writeln!(sk_buf, "{}", comment)?;
    } else {
        writeln!(sk_buf, "{}", rsign::SECRETKEY_DEFAULT_COMMENT)?;
    }
    writeln!(sk_buf, "{}", base64::encode(&sk_str.bytes()))?;
    sk_buf.flush()?;

    println!("\nThe secret key was saved as {} - Keep it secret!",
             path_sk.display());
    println!("The public key was saved as {} - That one can be public.\n",
             path_pk);
    println!("Files signed using this key pair can be verified with the following command:\n");
    println!("rsign verify -m <file> -P {}",
             base64::encode(pk_str.bytes().as_slice()));

    Ok(())
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
            .and(writeln!(io::stdout(), "Done!").map_err(|e| PError::new(ErrorKind::Io, e)))?;

    Ok(sk_str)
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
            base64::decode(encoded_buf.trim())
                .map_err(|e| PError::new(ErrorKind::Io, e))
                .and_then(|decoded_buf| PubkeyStruct::from(&decoded_buf))
        })?;
    Ok(pk)
}
fn pk_load_string(pk_string: &str) -> Result<PubkeyStruct> {
    let pk = String::from_str(pk_string)
        .map_err(|e| PError::new(ErrorKind::Io, e))
        .and_then(|string| {
                      base64::decode(string.as_bytes())
                          .map_err(|e| PError::new(ErrorKind::Io, e))
                          .and_then(|decoded_string| PubkeyStruct::from(&decoded_string))
                  })?;
    Ok(pk)
}

fn sign<P>(sk_key: SeckeyStruct,
           pk_key: Option<PubkeyStruct>,
           mut sig_buf: BufWriter<File>,
           message_file: P,
           trusted_comment: Option<&str>,
           untrusted_comment: Option<&str>,
            hashed: bool)
           -> Result<()>
    where P: AsRef<Path> + Copy + Display
{
    let t_comment = if let Some(trusted_comment) = trusted_comment {
        format!("{}", trusted_comment)
    } else {
        format!("timestamp:{} file:{}", Utc::now().timestamp(), message_file)
    };

    let unt_comment = if let Some(untrusted_comment) = untrusted_comment {
        format!("{}{}", COMMENT_PREFIX, untrusted_comment)
    } else {
        format!("{}{}", COMMENT_PREFIX, DEFAULT_COMMENT)
    };
    let msg_buf = load_message_file(message_file, &hashed)?;
    
    let mut sig_str = SigStruct::default();
    if !hashed {
        sig_str.sig_alg = sk_key.sig_alg.clone();
    } else {
        sig_str.sig_alg = SIGALG_HASHED;
    }
    sig_str
        .keynum
        .copy_from_slice(&sk_key.keynum_sk.keynum[..]);

    let sk =
        SecretKey::from_slice(&sk_key.keynum_sk.sk)
            .ok_or(PError::new(ErrorKind::Sign, "Couldn't generate secret key from bytes" ))?;

    let signature = sodiumoxide::crypto::sign::sign_detached(&msg_buf, &sk);

    sig_str.sig.copy_from_slice(&signature[..]);

    let mut sig_and_trust_comment: Vec<u8> = vec![];
    sig_and_trust_comment.extend(sig_str.sig.iter());
    sig_and_trust_comment.extend(t_comment.as_bytes().iter());

    let global_sig = sodiumoxide::crypto::sign::sign_detached(&sig_and_trust_comment, &sk);

    if let Some(pk_str) = pk_key {
        let pk = PublicKey::from_slice(&pk_str.keynum_pk.pk[..]).unwrap();
        if !sodiumoxide::crypto::sign::verify_detached(&global_sig, &sig_and_trust_comment, &pk) {
            panic!("Could not verify signature with the provided public key");
        } else {
            println!("\nSignature checked with the given public key!");;
        }
    }
    
    writeln!(sig_buf, "{}", unt_comment)?;
    writeln!(sig_buf, "{}", base64::encode(&sig_str.bytes()))?;
    writeln!(sig_buf, "{}{}", TRUSTED_COMMENT_PREFIX, t_comment)?;
    writeln!(sig_buf, "{}", base64::encode(&global_sig[..]))?;
    sig_buf.flush()?;
    Ok(())
}

fn verify<P>(pk_key: PubkeyStruct, sig_file: P, message_file: P) -> Result<()>
    where P: AsRef<Path> + Copy + Display
{
    let mut hashed: bool = false;

    let mut trusted_comment: Vec<u8> = Vec::with_capacity(TRUSTEDCOMMENTMAXBYTES);
    let mut global_sig: Vec<u8> = Vec::with_capacity(SIGNATUREBYTES);
    let sig = sig_load(sig_file, &mut global_sig, &mut trusted_comment, &mut hashed)?;

    let message = load_message_file(message_file, &hashed)?;
    if sig.keynum != pk_key.keynum_pk.keynum {
        return Err(PError::new(ErrorKind::Verify, format!("Public key ID: {:X} is not equal to signature key ID: {:X}",
                                                  rsign::load_usize_le(&pk_key.keynum_pk.keynum
                                                                            [..]),
                                                  rsign::load_usize_le(&sig.keynum[..]))));
    }
    Signature::from_slice(&sig.sig)
        .ok_or(PError::new(ErrorKind::Verify, "Couldn't compose message file signature from bytes"))
        .and_then(|signature| {
            PublicKey::from_slice(&pk_key.keynum_pk.pk)
                .ok_or(PError::new(ErrorKind::Verify, "Couldn't compose a public key from bytes"))
                .and_then(|pk|{
                        if sign::verify_detached(&signature, &message, &pk) {
                              println!("Message signature verified!");
                              Ok(pk)
                        } else {
                              return Err(PError::new(ErrorKind::Verify, "while verify message file signature"));
                                                                    
                        }
                })
                .and_then(|pk| {
                    Signature::from_slice(&global_sig[..])
                        .ok_or(PError::new(ErrorKind::Verify, "Couldn't compose trusted comment signature from bytes"))
                        .and_then(|global_sig|{
                            if sign::verify_detached(&global_sig, &trusted_comment, &pk) {
                              println!("Trusted comment signature verified!");
                              Ok(())
                            } else {
                                return Err(PError::new(ErrorKind::Verify, "Trusted comment verification failed!"));
                            }
                        })   
                })
        })
}
fn sig_load<P>(sig_file: P,
               global_sig: &mut Vec<u8>,
               trusted_comment: &mut Vec<u8>,
               hashed: &mut bool)
               -> Result<SigStruct>
    where P: AsRef<Path> + Copy + Display
{
    File::open(sig_file)
        .map_err(|e| PError::new(ErrorKind::Io, format!("{} {}", e, sig_file)))
        .and_then(|file| {
            let mut buf = BufReader::new(file);
            let mut untrusted_comment = String::with_capacity(COMMENTBYTES);
            buf.read_line(&mut untrusted_comment)
            .map_err(|e| PError::new(ErrorKind::Io, e))
            .and_then(|_|{
                let mut sig_string = String::with_capacity(SigStruct::len());
                buf.read_line(&mut sig_string)
                .map_err(|e| PError::new(ErrorKind::Io, e))
                .and_then(|_|{
                    let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
                    buf.read_line(&mut t_comment)
                    .map_err(|e| PError::new(ErrorKind::Io, e))
                    .and_then(|_|{
                        let mut g_sig = String::with_capacity(SIGNATUREBYTES);
                        buf.read_line(&mut g_sig)
                        .map_err(|e| PError::new(ErrorKind::Io, e))
                        .and_then(|_|{
                            if !untrusted_comment.starts_with(COMMENT_PREFIX) {
                                return Err(PError::new(ErrorKind::Verify, format!("Untrusted comment must start with: {}", COMMENT_PREFIX)));
                            }
                            base64::decode(sig_string.trim().as_bytes())
                                .map_err(|e| PError::new(ErrorKind::Io, e))
                                .and_then(|sig_bytes| {
                                    SigStruct::from(&sig_bytes)
                                    .and_then(|sig| {
                                        if !t_comment.starts_with(TRUSTED_COMMENT_PREFIX) {
                                            return Err(PError::new(ErrorKind::Verify, format!("trusted comment should start with: {}",
                                                            TRUSTED_COMMENT_PREFIX)));
                                        }
                                        if sig.sig_alg == SIGALG {
                                            *hashed = false;
                                        } else if sig.sig_alg == SIGALG_HASHED {
                                            *hashed = true;
                                        } else {
                                            return Err(PError::new(ErrorKind::Verify, format!("Unsupported signature algorithm")));
                                        }
                                        let _ = t_comment.drain(..TR_COMMENT_PREFIX_LEN).count();
                                        trusted_comment.extend(sig.sig.iter());
                                        trusted_comment.extend_from_slice(t_comment.trim().as_bytes());
                                        base64::decode(g_sig.trim().as_bytes())
                                        .map_err(|e| PError::new(ErrorKind::Io, e))
                                        .and_then(|comm_sig|{
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
    where P: AsRef<Path> + Copy + Display
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
                return Err(PError::new(ErrorKind::Io, format!("{} is larger than 1G try using -H",
                                                   message_file)));
            }
            let mut msg_buf: Vec<u8> = Vec::new();
            file.read_to_end(&mut msg_buf)?;
            Ok(msg_buf)
        })
}

fn hash_message_file<P>(message_file: P) -> Result<Vec<u8>>
    where P: AsRef<Path> + Copy + Display
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
pub fn run<'a>(args: clap::ArgMatches<'a>) -> Result<()>{
    if let Some(generate_action) = args.subcommand_matches("generate") {
        
        let pk_path = match generate_action.value_of("pk_path") {
            Some(path) => path,
            None => SIG_DEFAULT_PKFILE,
        };
        let sk_dir = generate_action.value_of("sk_path").map_or(None, |path|{ Some(PathBuf::from(path))});
        match sk_dir {
            Some(path) => path,
            None => {
                let path = std::env::var(SIG_DEFAULT_CONFIG_DIR_ENV_VAR)
                    .and_then(|var|{
                        Ok(PathBuf::from(var))
                    });
            },
        }
        let sk_path = match sk_dir {
            Some(mut dir) => {
                dir.push(SIG_DEFAULT_SKFILE);
                Some(dir)
                },
            None => {
               std::env::home_dir()
                .ok_or(PError::new(ErrorKind::Generate, "Could not find home dir"))
                .and_then(|mut home_dir| {
                    home_dir.push(SIG_DEFAULT_CONFIG_DIR);
                    home_dir.push(SIG_DEFAULT_SKFILE);
                    Ok(home_dir)
                })
                .ok()
            },
        };
        generate_keys(pk_path,
                              sk_path.unwrap().to_str().unwrap(),
                              generate_action.value_of("comment"),
                              generate_action.is_present("force"))?;
    }

    if let Some(sign_action) = args.subcommand_matches("sign") {
        let mut sk_path = std::env::home_dir().unwrap_or(PathBuf::new());
        sk_path.push(SIG_DEFAULT_CONFIG_DIR);
        sign_action.value_of("sk_path")
            .ok_or(PError::new(ErrorKind::Sign, "cannot find sk_path"))
            .and_then(|file_name| {
                sk_path.push(file_name);
                Ok(())
            }).unwrap();
        if sign_action.occurrences_of("sk_path") != 0 {
            sk_path = PathBuf::new();
            sk_path.push(sign_action.value_of("sk_path").unwrap());
        }
        let mut pk: Option<PubkeyStruct> = None;
        if sign_action.is_present("pk_path") {
            if let Some(filename) = sign_action.value_of("pk_path") {
                pk = Some(pk_load(filename).unwrap_or_else(|e| e.exit())) ;
            }
        } else if sign_action.is_present("public_key") {
            if let Some(string) = sign_action.value_of("public_key") {
                pk = Some(pk_load_string(string).unwrap_or_else(|e| e.exit()));
            }
        }
        let hashed = sign_action.is_present("hash");
        let message_file = sign_action.value_of("message").unwrap(); // required
        
        let sig_file_name = if let Some(file) = sign_action.value_of("sig_file") {
            format!("{}", file)
        } else {
            format!("{}{}", message_file, SIG_SUFFIX)
        };
        let sig_buf = create_sig_file(&sig_file_name)?;

        let sk = sk_load(sk_path).unwrap_or_else(|e| e.exit());
        sign(sk,
                     pk,
                     sig_buf,
                     message_file,
                     sign_action.value_of("trusted-comment"),
                     sign_action.value_of("untrusted-comment"),
                     hashed)?;
    }

    if let Some(verify_action) = args.subcommand_matches("verify") {
        let pk = verify_action
            .value_of("pk_path")
            .ok_or_else(|| PError::new(ErrorKind::Verify, "Could not find a public key"))
            .and_then(|pk_path| {
                pk_load(pk_path)
                    .map_err(|e| e.exit())
            });


        let sig_file = verify_action.value_of("sig_file").unwrap();
        let message_file = verify_action.value_of("file").unwrap();
        verify(pk.unwrap(), sig_file, message_file)?;
    }
    Ok(())
}

fn main() {
    let args = parse_args();
    run(args).map_err(|e| e.exit()).unwrap();
    std::process::exit(0);
}
