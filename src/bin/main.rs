extern crate rsign;
extern crate sodiumoxide;
extern crate base64;
extern crate libsodium_sys as ffi;
extern crate rpassword;
extern crate chrono;

use rsign::*;

use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey, Signature, SIGNATUREBYTES, SECRETKEYBYTES};
use sodiumoxide::crypto::pwhash::{self, MemLimit, OpsLimit};
use chrono::prelude::*;

use std::fmt::Display;
use std::io::{self, BufWriter, BufReader, BufRead, Read, Write};
use std::fs::{OpenOptions, File};
use std::path::Path;
use std::str::FromStr;


fn create_file_rw<P: AsRef<Path>>(path: P) -> Result<BufWriter<File>> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| PError::from(e))
        .and_then(|file| Ok(BufWriter::new(file)))
}

fn get_password(prompt: &str) -> Result<String> {
    let pwd = rpassword::prompt_password_stdout(prompt)?;
    if pwd.len() == 0 {
        Err(PError::PasswordError("can't be blank".to_owned()))
    } else if pwd.len() > PASSWORDMAXBYTES {
        Err(PError::PasswordError("can't exceed 1024 bytes lenght".to_owned()))
    } else {
        Ok(pwd)
    }
}

fn derive_and_crypt(sk_str: &mut SeckeyStruct, pwd: &[u8]) -> Result<()> {
    let mut stream = [0u8; BYTES + SECRETKEYBYTES + KEYNUMBYTES];
    pwhash::Salt::from_slice(&sk_str.kdf_salt)
        .ok_or_else(|| PError::Generic("Failed to generate Salt from random bytes".to_owned()))
        .and_then(|salt| {

            pwhash::derive_key(&mut stream,
                               &pwd,
                               &salt,
                               OpsLimit(load_usize_le(&sk_str.kdf_opslimit_le)),
                               MemLimit(load_usize_le(&sk_str.kdf_memlimit_le)))
                    .map_err(|_| PError::Generic("Failed to derive key from password".to_owned()))

        })?;
    sk_str.xor_keynum(&stream);
    Ok(())
}


fn generate_keys<P>(path_pk: P, path_sk: P, comment: Option<&str>, force: bool) -> Result<()>
    where P: AsRef<Path> + Copy + Display
{
    if !force && (path_pk.as_ref().exists() || path_sk.as_ref().exists()) {
        return Err(PError::Generic(format!("You already have keys at {} and {} try using --force if you want to overwrite",
                                           path_pk,
                                           path_sk)));
    }

    let (pk_str, mut sk_str) = gen_keystruct();
    sk_str
        .checksum()
        .map_err(|_| PError::Generic("Failed to hash and write checksum!".to_owned()))?;
    let pwd = get_password("Password: ")?;
    let pwd2 = get_password("Password (one more time): ")?;
    if pwd != pwd2 {
        return Err(PError::PasswordError("passwords don't match!".to_owned()));
    }

    write!(io::stdout(), "Deriving a key from password... ")
        .map_err(|e| PError::from(e))
        .and_then(|_| {
                      io::stdout().flush()?;
                      derive_and_crypt(&mut sk_str, &pwd.as_bytes())
                  })
        .and(writeln!(io::stdout(), "Done!").map_err(|e| PError::from(e)))?;

    let mut pk_buf = create_file_rw(path_pk)?;
    write!(pk_buf, "{}rsign public key: ", rsign::COMMENT_PREFIX)?;
    writeln!(pk_buf,
             "{:X}",
             rsign::load_usize_le(&pk_str.keynum_pk.keynum[..]))?;
    writeln!(pk_buf, "{}", base64::encode(&pk_str.bytes()))?;
    pk_buf.flush()?;

    let mut sk_buf = create_file_rw(path_sk)?;
    write!(sk_buf, "{}", rsign::COMMENT_PREFIX)?;
    if let Some(comment) = comment {
        writeln!(sk_buf, "{}", comment)?;
    } else {
        writeln!(sk_buf, "{}", rsign::SECRETKEY_DEFAULT_COMMENT)?;
    }
    writeln!(sk_buf, "{}", base64::encode(&sk_str.bytes()))?;
    sk_buf.flush()?;

    println!("\nThe secret key was saved as {} - Keep it secret!",
             path_sk);
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
        .map_err(|e| PError::from(e))
        .and_then(|file| {
            let mut sk_buf = BufReader::new(file);
            let mut _comment = String::new();
            sk_buf.read_line(&mut _comment)?;
            let mut encoded_buf = String::new();
            sk_buf.read_line(&mut encoded_buf)?;
            base64::decode(encoded_buf.trim())
                .map_err(|e| PError::from(e))
                .and_then(|decoded_buf| SeckeyStruct::from(&decoded_buf[..]))

        })?;

    let pwd = get_password("Password: ")?;
    write!(io::stdout(),
           "Deriving a key from the password and decrypting the secret key... ")
            .map_err(|e| PError::from(e))
            .and_then(|_| {
                          io::stdout().flush()?;
                          derive_and_crypt(&mut sk_str, &pwd.as_bytes())
                      })
            .and(writeln!(io::stdout(), "Done!").map_err(|e| PError::from(e)))?;

    Ok(sk_str)
}

fn pk_load<P: AsRef<Path>>(pk_path: P) -> Result<PubkeyStruct> {
    let pk = OpenOptions::new()
        .read(true)
        .open(pk_path)
        .map_err(|e| PError::from(e))
        .and_then(|file| {
            let mut pk_buf = BufReader::new(file);
            let mut _comment = String::new();
            pk_buf.read_line(&mut _comment)?;
            let mut encoded_buf = String::new();
            pk_buf.read_line(&mut encoded_buf)?;
            base64::decode(encoded_buf.trim())
                .map_err(|e| PError::from(e))
                .and_then(|decoded_buf| PubkeyStruct::from(&decoded_buf))
        })?;
    Ok(pk)
}
fn pk_load_string(pk_string: &str) -> Result<PubkeyStruct> {
    let pk = String::from_str(pk_string)
        .map_err(|e| PError::from(e))
        .and_then(|string| {
                      base64::decode(string.as_bytes())
                          .map_err(|e| PError::from(e))
                          .and_then(|decoded_string| PubkeyStruct::from(&decoded_string))
                  })?;
    Ok(pk)
}

fn sign<P>(sk_key: SeckeyStruct,
           pk_key: Option<PubkeyStruct>,
           sig_file: Option<P>,
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
    let sig_file_name = if let Some(file) = sig_file {
        format!("{}", file)
    } else {
        format!("{}{}", message_file, SIG_SUFFIX)
    };

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
            .ok_or(PError::SecretKeyError("Couldn't generate secret key from bytes".to_owned()))?;

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
    let mut sig_buf = create_file_rw(sig_file_name)?;
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
        return Err(PError::PublicKeyError(format!("Public key ID: {:X} is not equal to signature key ID: {:X}",
                                                  rsign::load_usize_le(&pk_key.keynum_pk.keynum
                                                                            [..]),
                                                  rsign::load_usize_le(&sig.keynum[..]))));
    }
    Signature::from_slice(&sig.sig)
        .ok_or(PError::SignatureError("Couldn't compose a signature from bytes".to_owned()))
        .and_then(|signature| {
            PublicKey::from_slice(&pk_key.keynum_pk.pk)
                .ok_or(PError::PublicKeyError("Couldn't compose a public key from bytes"
                                                  .to_owned()))
                .and_then(|pk| if sign::verify_detached(&signature, &message, &pk) {
                              println!("\nMessage signature verified!");
                              Ok(())
                          } else {
                              return Err(PError::SignatureError("Signature verification FAILED!"
                                                                    .to_owned()));
                          })
        })
}
fn sig_load<P>(sig_file: P,
               global_sig: &mut Vec<u8>,
               trusted_comment: &mut Vec<u8>,
               hashed: &mut bool)
               -> Result<SigStruct>
    where P: AsRef<Path> + Copy
{

    File::open(sig_file).map_err(|e| PError::from(e))
        .and_then(|file| {
            let mut buf = BufReader::new(file);
            
            let mut untrusted_comment = String::with_capacity(COMMENTBYTES);
            buf.read_line(&mut untrusted_comment)?;
            if !untrusted_comment.starts_with(COMMENT_PREFIX) {
                
            }
            let mut sig_string = String::with_capacity(SigStruct::len());
            buf.read_line(&mut sig_string)?;
            let sig = SigStruct::from(&base64::decode(sig_string.trim().as_bytes())?)?;

            if sig.sig_alg == SIGALG {
                *hashed = false;
            } else if sig.sig_alg == SIGALG_HASHED {
                *hashed = true;
            } else {
                return Err(PError::Generic(format!("Unsupported signature algorithm")));
            }

            let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
            buf.read_line(&mut t_comment)?;
            if !t_comment.starts_with(TRUSTED_COMMENT_PREFIX) {
                return Err(PError::CommentError(format!("trusted comment should start with: {}",
                                                TRUSTED_COMMENT_PREFIX)));
            }
            let _ = t_comment.drain(..TR_COMMENT_PREFIX_LEN).count();
            trusted_comment.extend_from_slice(t_comment.trim().as_bytes());
            
            let mut g_sig = String::with_capacity(SIGNATUREBYTES);
            buf.read_line(&mut g_sig)?;
            global_sig.extend_from_slice(g_sig.trim().as_bytes());
            
            Ok(sig)
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
        .map_err(|e| PError::from(e))
        .and_then(|mut file| {
                      if file.metadata().unwrap().len() > (1u64 << 30) {
                          return Err(PError::Generic(format!("File {} is larger than 1G try using -H", message_file)));
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
        .map_err(|e| PError::from(e))
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


fn main() {

    let args = parse_args();
    sodiumoxide::init();

    if let Some(generate_action) = args.subcommand_matches("generate") {
        //TODO: add parent folder to sk_file_path
        let _ = generate_keys(generate_action
                                  .value_of("pk_path")
                                  .expect("pk file path"),
                              generate_action
                                  .value_of("sk_path")
                                  .expect("sk file path"),
                              generate_action.value_of("comment"),
                              generate_action.is_present("force"))
                .unwrap_or_else(|e| e.exit());

    }

    if let Some(sign_action) = args.subcommand_matches("sign") {
        let sk_file = sign_action.value_of("sk_path").unwrap();
        let mut pk: Option<PubkeyStruct> = None;
        if sign_action.is_present("pk_path") {
            if let Some(filename) = sign_action.value_of("pk_path") {
                pk = Some(pk_load(filename).unwrap());
            }
        } else if sign_action.is_present("public_key") {
            if let Some(string) = sign_action.value_of("public_key") {
                pk = Some(pk_load_string(string).unwrap());
            }
        }

        let sk = sk_load(sk_file).unwrap_or_else(|e| e.exit());
        let _ = sign(sk,
                     pk,
                     sign_action.value_of("sig_file"),
                     sign_action.value_of("message").unwrap(),
                     sign_action.value_of("trusted-comment"),
                     sign_action.value_of("untrusted-comment"),
                     sign_action.is_present("hash"));
    }

    if let Some(verify_action) = args.subcommand_matches("verify") {
        let pk = verify_action
            .value_of("pk_path")
            .ok_or_else(|| PError::Error.exit())
            .and_then(|pk_path| pk_load(pk_path).map_err(|e| e.exit()));


        let sig_file = verify_action.value_of("sig_file").unwrap();
        let message_file = verify_action.value_of("file").unwrap();
        let _ = verify(pk.unwrap(), sig_file, message_file);
    }


}
