extern crate rsign;
extern crate sodiumoxide;
extern crate base64;
extern crate libsodium_sys as ffi;
extern crate rpassword;
extern crate chrono;

use rsign::parse_args::parse_args;
use rsign::{SeckeyStruct, PubkeyStruct, SigStruct, COMMENTBYTES, TRUSTED_COMMENT_PREFIX,
            TRUSTEDCOMMENTMAXBYTES, COMMENT_PREFIX, DEFAULT_COMMENT, SIG_SUFFIX};

use sodiumoxide::crypto::sign::{PublicKey, SecretKey, Signature};
use sodiumoxide::crypto::pwhash;
use chrono::prelude::*;

use std::fmt;
use std::io::prelude::*;
use std::io::{self, BufWriter, BufReader, Stdout};
use std::fs::{OpenOptions, File};
use std::path::Path;
use std::process;
use std::str::FromStr;

fn create_file<P: AsRef<Path>>(path_pk: P,
                               path_sk: P)
                               -> Result<(BufWriter<File>, BufWriter<File>), ()> {
    let sk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path_sk)
        .unwrap();
    let pk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path_pk)
        .unwrap();

    Ok((BufWriter::new(pk_file), BufWriter::new(sk_file)))
}
fn create_sig_file<P: AsRef<Path>>(path: P) -> Result<BufWriter<File>, ()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
    Ok(BufWriter::new(file))
}

fn panic_if_file_exist<P: AsRef<Path>>(path_pk: P, path_sk: P) {
    if path_pk.as_ref().exists() || path_sk.as_ref().exists() {
        panic!("{}", "try to use -f if you want to overwrite keys");
    }
}

fn get_password() -> String {
    let pwd = rpassword::prompt_password_stdout("Password: ").unwrap();
    let pwd_conf = rpassword::prompt_password_stdout("Password (one more time): ").unwrap();
    if pwd != pwd_conf {
        writeln!(io::stderr(), "Passwords don't match").unwrap();
        process::exit(1);
    } else if pwd.len() == 0 {
        writeln!(io::stderr(), "<empty>").unwrap();
    }
    pwd
}

fn generate_keys<P: AsRef<Path> + Copy + fmt::Display>(path_pk: P,
                                                       path_sk: P,
                                                       comment: Option<&str>,
                                                       force: bool)
                                                       -> Result<(), io::Error> {
    if !force {
        panic_if_file_exist(&path_pk, &path_sk);
    }
    let (pk_str, mut sk_str) = rsign::gen_keystruct();
    sk_str.checksum();
    let pwd = get_password();
    write!(std::io::stdout(), "Deriving a key from password... ")?;
    std::io::stdout().flush();
    let salt = pwhash::Salt::from_slice(sk_str.kdf_salt.as_ref()).unwrap();
    let mut stream = vec![0u8; sk_str.keynum_sk.len()];
    pwhash::derive_key(stream.as_mut_slice(),
                       pwd.as_bytes(),
                       &salt,
                       sk_str.kdf_opslimit_le,
                       sk_str.kdf_memlimit_le)
            .unwrap();
    println!("Done!");
    sk_str.xor_keynum(stream);

    let (mut pk_buf, mut sk_buf) = create_file(path_pk, path_sk).unwrap();
    let pk_struct_bytes = pk_str.bytes();
    write!(pk_buf, "{}rsign public key: ", rsign::COMMENT_PREFIX)?;
    for byte in pk_str.keynum_pk.keynum.into_iter() {
        write!(pk_buf, "{:X}", byte)?;
    }
    pk_buf.write(b"\n")?;
    writeln!(pk_buf, "{}", base64::encode(pk_struct_bytes.as_slice()))?;
    pk_buf.flush().unwrap();

    write!(sk_buf, "{}", rsign::COMMENT_PREFIX)?;
    writeln!(sk_buf, "{}", rsign::SECRETKEY_DEFAULT_COMMENT).unwrap();
    writeln!(sk_buf, "{}", base64::encode(sk_str.bytes().as_slice())).unwrap();
    sk_buf.flush().unwrap();

    println!("The secret key was saved as {} - Keep it secret!", path_sk);
    println!("The public key was saved as {} - That one can be public.\n",
             path_pk);
    println!("Files signed using this key pair can be verified with the following command:\n");
    println!("rsign -Vm <file> -P {}",
             base64::encode(&pk_str.keynum_pk.pk[..]));
    sodiumoxide::utils::memzero(&mut sk_str.keynum_sk.sk);
    sodiumoxide::utils::memzero(&mut sk_str.kdf_salt);
    sodiumoxide::utils::memzero(&mut sk_str.keynum_sk.chk);

    Ok(())
}

fn sk_load<P: AsRef<Path>>(sk_path: P) -> SeckeyStruct {
    let sk_file = OpenOptions::new().read(true).open(sk_path).unwrap();
    let mut sk_buf = BufReader::new(sk_file);
    let mut _comment = String::new();
    sk_buf.read_line(&mut _comment);
    let mut encoded_buf = vec![];
    let bcount = sk_buf
        .read_until(b'\n', &mut encoded_buf)
        .expect("error reading buffer");
    let mut decoded_buf: Vec<u8> =
        base64::decode(&encoded_buf[..bcount - 1]).expect("Fail decoding b64 stream");
    let mut sk = SeckeyStruct::from(&decoded_buf[..]).unwrap();

    let pwd = get_password();
    write!(std::io::stdout(), "Deriving a key from password... ").unwrap();
    std::io::stdout().flush();
    let salt = pwhash::Salt::from_slice(sk.kdf_salt.as_ref()).unwrap();
    let mut stream = vec![0u8; sk.keynum_sk.len()];
    pwhash::derive_key(stream.as_mut_slice(),
                       pwd.as_bytes(),
                       &salt,
                       sk.kdf_opslimit_le,
                       sk.kdf_memlimit_le)
            .unwrap();
    println!("Done!");
    sk.xor_keynum(stream);

    sk
}

fn pk_load<P: AsRef<Path>>(pk_path: P) -> PubkeyStruct {
    let pk_file = OpenOptions::new()
        .read(true)
        .open(pk_path)
        .expect("Error opening public key file");
    let mut pk_buf = BufReader::new(pk_file);
    let mut _comment = String::new();
    pk_buf.read_line(&mut _comment);
    let mut encoded_stream = vec![];
    let bcount = pk_buf
        .read_until(b'\n', &mut encoded_stream)
        .expect("error reading buffer");
    let mut decoded_stream =
        base64::decode(&encoded_stream[..bcount - 1]).expect("fail decoding pk");
    let pk = PubkeyStruct::from(&decoded_stream[..]);
    pk
}
fn pk_load_string(pk_string: &str) -> PubkeyStruct {
    let pk_string = String::from_str(pk_string).unwrap();
    let decoded = base64::decode(pk_string.as_bytes()).expect("fail to decode pk string");
    let pk = PubkeyStruct::from(&decoded[..]);
    pk
}

fn sign<P: AsRef<Path>>(sk_key: SeckeyStruct,
                        pk_key: PubkeyStruct,
                        sig_file: Option<P>,
                        message_file: P,
                        trusted_comment: Option<&str>,
                        untrusted_comment: Option<&str>,
                        hashed: bool) {
    let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
    let mut unt_comment = String::with_capacity(COMMENTBYTES);
    let utc: DateTime<Utc> = Utc::now();
    let message_file_name = String::from_str(message_file.as_ref().file_name().unwrap().to_str().unwrap()).unwrap();
    if let Some(trusted_comment) = trusted_comment {
        t_comment = format!("{}{}", TRUSTED_COMMENT_PREFIX, trusted_comment);
    } else {
        t_comment = format!("{} timestamp:{} file:{}",
                            TRUSTED_COMMENT_PREFIX,
                            utc.timestamp(),
                            message_file_name);
    }
    if let Some(untrusted_comment)  = untrusted_comment {
        unt_comment = format!("{}{}", COMMENT_PREFIX, untrusted_comment);
    } else {
        unt_comment = format!("{}{}", COMMENT_PREFIX, DEFAULT_COMMENT);
    }
    let mut msg = load_message_file(message_file).expect("Error opening file to sign");
    let mut msg_buf: Vec<u8> = Vec::new();
    msg.read_to_end(&mut msg_buf);
    let mut sig_file_name = String::new();
    if let Some(file) = sig_file {
        sig_file_name = String::from_str(file.as_ref().to_str().unwrap()).unwrap();
    } else {
        sig_file_name = format!("{}{}", 
                message_file_name, 
                SIG_SUFFIX);
    }
    let mut sig_buf = create_sig_file(sig_file_name).unwrap();
    let mut sig_str = SigStruct::default();
    sig_str.sig_alg.clone_from(sk_key.kdf_alg.as_ref());
    sig_str.keynum.clone_from(sk_key.keynum_sk.keynum.as_ref());
    let signature = sodiumoxide::crypto::sign::sign_detached(msg_buf.as_ref(), &SecretKey::from_slice(sk_key.keynum_sk.sk.as_ref()).unwrap());
    sig_str.sig.clone_from(&signature[..].to_vec());
    let mut sig_and_trust_comment: Vec<u8> = vec![];
    sig_and_trust_comment.extend(t_comment.as_bytes().iter());
    sig_and_trust_comment.extend(sig_str.bytes().iter());
    let sig_comment = sodiumoxide::crypto::sign::sign_detached(sig_and_trust_comment.as_ref(), &SecretKey::from_slice(sk_key.keynum_sk.sk.as_ref()).unwrap());
    writeln!(sig_buf, "{}", unt_comment);
    writeln!(sig_buf, "{}", base64::encode(&signature[..]));
    writeln!(sig_buf, "{}", t_comment);
    writeln!(sig_buf, "{}", base64::encode(&sig_comment[..]));
    sig_buf.flush();
}
fn load_message_file<P: AsRef<Path>>(message_file: P) -> Result<BufReader<File>, ()> {
    let file = OpenOptions::new()
        .read(true)
        .open(message_file)
        .expect("error opening file");
    Ok(BufReader::new(file))
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
                              generate_action.is_present("force"));

    }

    if let Some(sign_action) = args.subcommand_matches("sign") {
        let sk_file = sign_action.value_of("sk_path").unwrap();
        let pk_file = rsign::SIG_DEFAULT_PKFILE;
        //TODO check sig_file command line parameter or use default

        let _ = sign(sk_load(sk_file),
                     pk_load(pk_file),
                     sign_action.value_of("sig_file"),
                     sign_action.value_of("message").unwrap(),
                     sign_action.value_of("trusted-comment"),
                     sign_action.value_of("untrusted-comment"),
                     sign_action.is_present("hash"));
    }

    /* if let Some(verify_action) = args.subcommand_matches("verify") {
        let public_key = get_key_from_file(verify_action.value_of("public_key").unwrap());
        let mut message_to_verify = String::new();
        open_file(verify_action.value_of("file").unwrap())
            .read_to_string(&mut message_to_verify)
            .unwrap();
        let sig = get_signature_from_file(verify_action.value_of("sig_file").unwrap());
        if sign::verify_detached(&Signature::from_slice(&sig).unwrap(),
                                 message_to_verify.as_bytes(),
                                 &PublicKey::from_slice(&public_key).unwrap()) {
            println!("{} is verified against signature {}",
                     verify_action.value_of("file").unwrap(),
                     verify_action.value_of("sig_file").unwrap());
        } else {
            println!("{}", "Could'nt verify this file!");
        } 
    }*/


}
