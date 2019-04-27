extern crate base64;
extern crate chrono;
extern crate clap;
extern crate dirs;
extern crate rsign2;

use chrono::prelude::*;
use rsign2::crypto::blake2b::Blake2b;
use rsign2::crypto::digest::Digest;
use rsign2::*;
use std::fmt::Debug;

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read};
#[cfg(not(windows))]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn create_dir<P>(path: P) -> Result<()>
where
    P: AsRef<Path> + Debug,
{
    DirBuilder::new()
        .recursive(true)
        .create(&path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))?;
    Ok(())
}

#[cfg(windows)]
fn create_file<P>(path: P, _mode: u32) -> Result<BufWriter<File>>
where
    P: AsRef<Path> + Copy + Debug,
{
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))?;
    Ok(BufWriter::new(file))
}

#[cfg(not(windows))]
fn create_file<P>(path: P, mode: u32) -> Result<BufWriter<File>>
where
    P: AsRef<Path> + Copy + Debug,
{
    let file = OpenOptions::new()
        .mode(mode)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))?;
    Ok(BufWriter::new(file))
}

fn create_sig_file<P>(path: P) -> Result<BufWriter<File>>
where
    P: AsRef<Path> + Copy + Debug,
{
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .map_err(|e| PError::new(ErrorKind::Io, format!("while creating: {:?} - {}", path, e)))?;
    Ok(BufWriter::new(file))
}

fn load_and_hash_message_file<P>(message_file: P) -> Result<Vec<u8>>
where
    P: AsRef<Path> + Copy,
{
    let file = OpenOptions::new()
        .read(true)
        .open(message_file)
        .map_err(|e| PError::new(ErrorKind::Io, e))?;

    let mut buf_reader = BufReader::new(file);
    let mut buf_chunk = [0u8; 65536];
    let mut state = Blake2b::new(PREHASH_BYTES);
    while buf_reader.read(&mut buf_chunk).unwrap() > 0 {
        state.input(&buf_chunk);
    }
    let mut out = vec![0u8; PREHASH_BYTES];
    state.result(&mut out);
    Ok(out)
}

fn load_message_file<P>(message_file: P, hashed: bool) -> Result<Vec<u8>>
where
    P: AsRef<Path> + Copy + Debug,
{
    if hashed {
        return load_and_hash_message_file(message_file);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(message_file)
        .map_err(|e| PError::new(ErrorKind::Io, e))?;
    if file.metadata().unwrap().len() > (1u64 << 30) {
        Err(PError::new(
            ErrorKind::Io,
            format!("{:?} is larger than 1G try using -H", message_file),
        ))?;
    }
    let mut msg_buf: Vec<u8> = Vec::new();
    file.read_to_end(&mut msg_buf)?;
    Ok(msg_buf)
}

fn cmd_generate(
    force: bool,
    pk_path: PathBuf,
    sk_path_str: Option<&str>,
    comment: Option<&str>,
) -> Result<()> {
    if pk_path.exists() {
        if !force {
            Err(PError::new(
                ErrorKind::Io,
                format!(
                    "Key generation aborted:\n
{:?} already exists\n
If you really want to overwrite the existing key pair, add the -f switch to\n
force this operation.",
                    pk_path
                ),
            ))?;
        } else {
            std::fs::remove_file(&pk_path)?;
        }
    }

    let sk_path = match sk_path_str {
        Some(path) => {
            let complete_path = PathBuf::from(path);
            let mut dir = complete_path.clone();
            dir.pop();
            create_dir(dir)?;
            complete_path
        }
        None => {
            let env_path = std::env::var(SIG_DEFAULT_CONFIG_DIR_ENV_VAR);
            match env_path {
                Ok(env_path) => {
                    let mut complete_path = PathBuf::from(env_path);
                    if !complete_path.exists() {
                        Err(PError::new(
                            ErrorKind::Io,
                            format!(
                                "folder {:?} referenced by {} doesn't exists, you'll have to create yourself",
                                complete_path, SIG_DEFAULT_CONFIG_DIR_ENV_VAR
                            ),
                        ))?;
                    }
                    complete_path.push(SIG_DEFAULT_SKFILE);
                    complete_path
                }
                Err(_) => {
                    let home_path = dirs::home_dir()
                        .ok_or_else(|| PError::new(ErrorKind::Io, "can't find home dir"));
                    let mut complete_path = home_path.unwrap();
                    complete_path.push(SIG_DEFAULT_CONFIG_DIR);
                    if !complete_path.exists() {
                        create_dir(&complete_path)?;
                    }
                    complete_path.push(SIG_DEFAULT_SKFILE);
                    complete_path
                }
            }
        }
    };

    if sk_path.exists() {
        if !force {
            Err(PError::new(
                ErrorKind::Io,
                format!(
                    "Key generation aborted:
{:?} already exists

If you really want to overwrite the existing key pair, add the -f switch to
force this operation.",
                    sk_path
                ),
            ))?;
        } else {
            std::fs::remove_file(&sk_path)?;
        }
    }
    let pk_file = create_file(&pk_path, 0o644)?;
    let sk_file = create_file(&sk_path, 0o600)?;
    let (pk_str, _) = generate_keypair(pk_file, sk_file, comment)?;

    println!(
        "\nThe secret key was saved as {:?} - Keep it secret!",
        sk_path
    );
    println!(
        "The public key was saved as {:?} - That one can be public.\n",
        pk_path
    );
    println!("Files signed using this key pair can be verified with the following command:\n");
    println!(
        "rsign verify <file> -P {}",
        base64::encode(pk_str.to_bytes().as_slice())
    );
    Ok(())
}

fn cmd_sign(
    sk_path: PathBuf,
    pk: Option<PublicKey>,
    hashed: bool,
    sig_file_name: String,
    message_file: &str,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
) -> Result<()> {
    if !sk_path.exists() {
        Err(PError::new(
            ErrorKind::Io,
            format!("can't find secret key file at {:?}, try using -s", sk_path),
        ))?;
    }
    let sig_buf = create_sig_file(&sig_file_name)?;
    let sk = sk_load(sk_path)?;
    let t_comment = if let Some(trusted_comment) = trusted_comment {
        trusted_comment.to_string()
    } else {
        format!(
            "timestamp:{}\tfile:{}",
            Utc::now().timestamp(),
            message_file
        )
    };
    let unt_comment = if let Some(untrusted_comment) = untrusted_comment {
        format!("{}{}", COMMENT_PREFIX, untrusted_comment)
    } else {
        format!("{}{}", COMMENT_PREFIX, DEFAULT_COMMENT)
    };
    let message = load_message_file(message_file, hashed)?;
    sign(
        sk,
        pk,
        sig_buf,
        message.as_ref(),
        hashed,
        t_comment.as_str(),
        unt_comment.as_str(),
    )
}

fn cmd_verify(
    pk: PublicKey,
    message_file: &str,
    sig_file_name: String,
    quiet: bool,
    output: bool,
) -> Result<()> {
    let signature_box = SignatureBox::from_file(&sig_file_name)?;
    let message = load_message_file(message_file, signature_box.hashed)?;
    verify(
        pk,
        signature_box.signature,
        &signature_box.global_sig[..],
        signature_box.trusted_comment.as_ref(),
        message.as_ref(),
        quiet,
        output,
    )
}

fn run(args: clap::ArgMatches) -> Result<()> {
    if let Some(generate_action) = args.subcommand_matches("generate") {
        let force = generate_action.is_present("force");
        let pk_path = match generate_action.value_of("pk_path") {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(SIG_DEFAULT_PKFILE),
        };
        let sk_path_str = generate_action.value_of("sk_path");
        let comment = generate_action.value_of("comment");
        cmd_generate(force, pk_path, sk_path_str, comment)
    } else if let Some(sign_action) = args.subcommand_matches("sign") {
        let sk_path = match sign_action.value_of("sk_path") {
            Some(path) => PathBuf::from(path),
            None => {
                let home_path = dirs::home_dir()
                    .ok_or_else(|| PError::new(ErrorKind::Io, "can't find home dir"));
                let mut complete_path = home_path.unwrap();
                complete_path.push(SIG_DEFAULT_CONFIG_DIR);
                complete_path.push(SIG_DEFAULT_SKFILE);
                complete_path
            }
        };
        let mut pk = None;
        if sign_action.is_present("pk_path") {
            if let Some(filename) = sign_action.value_of("pk_path") {
                pk = Some(pk_load(filename)?);
            }
        } else if sign_action.is_present("public_key") {
            if let Some(string) = sign_action.value_of("public_key") {
                pk = Some(pk_load_string(string)?);
            }
        };
        let hashed = sign_action.is_present("hash");
        let message_file = sign_action.value_of("message").unwrap(); // safe to unwrap
        let sig_file_name = if let Some(file) = sign_action.value_of("sig_file") {
            file.to_string()
        } else {
            format!("{}{}", message_file, SIG_SUFFIX)
        };
        let trusted_comment = sign_action.value_of("trusted-comment");
        let untrusted_comment = sign_action.value_of("untrusted-comment");
        cmd_sign(
            sk_path,
            pk,
            hashed,
            sig_file_name,
            message_file,
            trusted_comment,
            untrusted_comment,
        )
    } else if let Some(verify_action) = args.subcommand_matches("verify") {
        let pk_path_str = verify_action
            .value_of("pk_path")
            .or_else(|| verify_action.value_of("public_key"));
        let pk = match pk_path_str {
            Some(path_or_string) => {
                if verify_action.is_present("pk_path") {
                    pk_load(path_or_string)?
                } else {
                    pk_load_string(path_or_string)?
                }
            }
            None => pk_load(SIG_DEFAULT_PKFILE)?,
        };
        let message_file = verify_action.value_of("file").unwrap();
        let sig_file_name = if let Some(file) = verify_action.value_of("sig_file") {
            file.to_string()
        } else {
            format!("{}{}", message_file, SIG_SUFFIX)
        };
        let quiet = verify_action.is_present("quiet");
        let output = verify_action.is_present("output");
        cmd_verify(pk, message_file, sig_file_name, quiet, output)
    } else {
        println!("{}\n", args.usage());
        std::process::exit(1);
    }
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
