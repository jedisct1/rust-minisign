extern crate rsign;
extern crate sodiumoxide;
extern crate base64;
extern crate libsodium_sys as ffi;
extern crate rpassword;
extern crate chrono;

use rsign::parse_args::parse_args;
use rsign::generichash;
use rsign::{SeckeyStruct, PubkeyStruct, SigStruct, COMMENTBYTES, TRUSTED_COMMENT_PREFIX,
            TRUSTEDCOMMENTMAXBYTES, COMMENT_PREFIX, DEFAULT_COMMENT, SIG_SUFFIX,
            TR_COMMENT_PREFIX_LEN, SIGALG_HASHED, SIGALG};

use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey, Signature, SIGNATUREBYTES};
use sodiumoxide::crypto::pwhash;
use chrono::prelude::*;

use std::fmt;
use std::io::prelude::*;
use std::io::{self, BufWriter, BufReader};
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
    std::io::stdout().flush().unwrap();
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
    write!(pk_buf, "{:X}", rsign::load_usize_le(&pk_str.keynum_pk.keynum[..]))?;
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
             base64::encode(pk_struct_bytes.as_slice()));
    sodiumoxide::utils::memzero(&mut sk_str.keynum_sk.sk);
    sodiumoxide::utils::memzero(&mut sk_str.kdf_salt);
    sodiumoxide::utils::memzero(&mut sk_str.keynum_sk.chk);

    Ok(())
}


fn sk_load<P: AsRef<Path>>(sk_path: P) -> Result<SeckeyStruct, io::Error> {
    let sk_file = OpenOptions::new().read(true).open(sk_path).unwrap();
    let mut sk_buf = BufReader::new(sk_file);
    let mut _comment = String::new();
    sk_buf.read_line(&mut _comment).unwrap();
    let mut encoded_buf = vec![];
    let bcount = sk_buf
        .read_until(b'\n', &mut encoded_buf)
        .expect("error reading buffer");
    let decoded_buf: Vec<u8> =
        base64::decode(&encoded_buf[..bcount - 1]).expect("Fail decoding b64 stream");
    let mut sk = SeckeyStruct::from(&decoded_buf[..]).unwrap();

    let pwd = get_password();
    write!(std::io::stdout(), "Deriving a key from password... ").unwrap();
    std::io::stdout().flush().unwrap();
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

    Ok(sk)
}

fn pk_load<P: AsRef<Path>>(pk_path: P) -> Result<PubkeyStruct, io::Error> {
    let pk_file = OpenOptions::new()
        .read(true)
        .open(pk_path)
        .expect("Error opening public key file");
    let mut pk_buf = BufReader::new(pk_file);
    let mut _comment = String::new();
    pk_buf.read_line(&mut _comment).unwrap();
    let mut encoded_stream = vec![];
    let bcount = pk_buf
        .read_until(b'\n', &mut encoded_stream)
        .expect("error reading buffer");
    let decoded_stream =
        base64::decode(&encoded_stream[..bcount - 1]).expect("fail decoding pk");
    let pk = PubkeyStruct::from(&decoded_stream[..]).unwrap();
    Ok(pk)
}
fn pk_load_string(pk_string: &str) -> Result<PubkeyStruct, io::Error> {
    let pk_string = String::from_str(pk_string).unwrap();
    let decoded = base64::decode(pk_string.as_bytes()).expect("fail to decode pk string");
    let pk = PubkeyStruct::from(&decoded[..]).unwrap();
    Ok(pk)
}

fn sign<P: AsRef<Path>>(sk_key: SeckeyStruct,
                        pk_key: Option<PubkeyStruct>,
                        sig_file: Option<P>,
                        message_file: P,
                        trusted_comment: Option<&str>,
                        untrusted_comment: Option<&str>,
                        hashed: bool) -> Result<(), io::Error>
    where P: std::marker::Copy
{
    let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
    let mut unt_comment = String::with_capacity(COMMENTBYTES);
    let utc: DateTime<Utc> = Utc::now();
    let message_file_name = String::from_str(message_file
                                                 .as_ref()
                                                 .file_name()
                                                 .unwrap()
                                                 .to_str()
                                                 .unwrap())
            .unwrap();
    if let Some(trusted_comment) = trusted_comment {
        t_comment = format!("{}", trusted_comment);
    } else {
        t_comment = format!("timestamp:{} file:{}", utc.timestamp(), message_file_name);
    }
    if let Some(untrusted_comment) = untrusted_comment {
        unt_comment = format!("{}{}", COMMENT_PREFIX, untrusted_comment);
    } else {
        unt_comment = format!("{}{}", COMMENT_PREFIX, DEFAULT_COMMENT);
    }
    let msg_buf: Vec<u8> = if hashed {
        load_and_hash_message_file(message_file)
    } else {
        load_message_file(message_file)
    };

    let mut sig_file_name = String::new();
    if let Some(file) = sig_file {
        sig_file_name = String::from_str(file.as_ref().to_str().unwrap()).unwrap();
    } else {
        sig_file_name = format!("{}{}", message_file_name, SIG_SUFFIX);
    }
    let mut sig_buf = create_sig_file(sig_file_name).unwrap();
    let mut sig_str = SigStruct::default();
    if !hashed {
        sig_str.sig_alg.clone_from(sk_key.sig_alg.as_ref());
    } else {
        sig_str
            .sig_alg
            .clone_from(&rsign::SIGALG_HASHED.as_bytes().to_vec());
    }
    sig_str
        .keynum
        .clone_from(sk_key.keynum_sk.keynum.as_ref());
    let signature =
        sodiumoxide::crypto::sign::sign_detached(msg_buf.as_ref(),
                                                 &SecretKey::from_slice(sk_key
                                                                            .keynum_sk
                                                                            .sk
                                                                            .as_ref())
                                                          .unwrap());
    sig_str.sig.clone_from(&signature[..].to_vec());

    let mut sig_and_trust_comment: Vec<u8> = vec![];
    sig_and_trust_comment.extend(sig_str.sig.iter());
    sig_and_trust_comment.extend(t_comment.as_bytes().iter());

    let global_sig =
        sodiumoxide::crypto::sign::sign_detached(sig_and_trust_comment.as_ref(),
                                                 &SecretKey::from_slice(sk_key
                                                                            .keynum_sk
                                                                            .sk
                                                                            .as_ref())
                                                          .unwrap());
    if let Some(pk_str) = pk_key {
        let pk = PublicKey::from_slice(&pk_str.keynum_pk.pk[..]).unwrap();
        if !sodiumoxide::crypto::sign::verify_detached(&global_sig, &sig_and_trust_comment, &pk) {
            panic!("Could not verify signature with the provided public key");
        } else {
            println!("Signature checked with the public key!");;
        }
    }

    writeln!(sig_buf, "{}", unt_comment).unwrap();
    writeln!(sig_buf, "{}", base64::encode(&sig_str.bytes())).unwrap();
    writeln!(sig_buf, "{}{}", TRUSTED_COMMENT_PREFIX, t_comment).unwrap();
    writeln!(sig_buf, "{}", base64::encode(&global_sig[..])).unwrap();
    sig_buf.flush().unwrap();
    Ok(())
}

fn verify<P>(pk_key: PubkeyStruct, sig_file: P, message_file: P, quiet: bool, output: bool)
    where P: AsRef<Path> + Copy
{
    let mut is_hashed: bool = false;
    let mut message = vec![];
    let mut trusted_comment: Vec<u8> = Vec::with_capacity(TRUSTEDCOMMENTMAXBYTES);
    let mut global_sig: Vec<u8> = Vec::with_capacity(SIGNATUREBYTES);
    let sig = sig_load(sig_file,
                       &mut global_sig,
                       &mut trusted_comment,
                       &mut is_hashed);
    if is_hashed {
        message = load_and_hash_message_file(message_file);
    } else {
        message = load_message_file(message_file);
    }
    if sig.keynum != pk_key.keynum_pk.keynum {
        panic!("Public key ID: {:X} is not equal to signature key ID: {:X}",
               rsign::load_usize_le(&pk_key.keynum_pk.keynum[..]),
               rsign::load_usize_le(&sig.keynum[..]));
    }
    if sign::verify_detached(&Signature::from_slice(&sig.sig[..]).unwrap(),
                             &message[..],
                             &PublicKey::from_slice(&pk_key.keynum_pk.pk[..]).unwrap()) {
        println!("Signature verified!");
    }

}
fn sig_load<P>(sig_file: P,
               global_sig: &mut Vec<u8>,
               trusted_comment: &mut Vec<u8>,
               is_hashed: &mut bool)
               -> SigStruct
    where P: AsRef<Path> + Copy
{
    let mut buf_r = BufReader::new(File::open(sig_file).unwrap());
    let mut untrusted_comment = String::with_capacity(COMMENTBYTES);
    let _ = buf_r.read_line(&mut untrusted_comment);
    if !untrusted_comment.starts_with(COMMENT_PREFIX) {
        panic!("untrusted comment should start with: {}", COMMENT_PREFIX);
    }
    let mut sig_str = String::with_capacity(74);
    let _ = buf_r.read_line(&mut sig_str);
    let sig_str = base64::decode(sig_str.trim().as_bytes()).unwrap();
    let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
    let _ = buf_r.read_line(&mut t_comment);
    if !t_comment.starts_with(TRUSTED_COMMENT_PREFIX) {
        panic!("trusted comment should start with: {}",
               TRUSTED_COMMENT_PREFIX);
    }
    let _ = t_comment.drain(..TR_COMMENT_PREFIX_LEN).count();

    trusted_comment.extend_from_slice(t_comment.trim().as_bytes());
    let mut g_sig = String::with_capacity(SIGNATUREBYTES);
    let _ = buf_r.read_line(&mut g_sig);
    global_sig.extend_from_slice(g_sig.trim().as_bytes());
    let sig = SigStruct::from(&sig_str[..]).unwrap();
    println!("{:?}", sig.sig_alg.clone());
    println!("{:?}", SIGALG.as_bytes().to_vec());
    if sig.sig_alg == SIGALG.as_bytes().to_vec() {
        *is_hashed = false;
    } else if sig.sig_alg == SIGALG_HASHED.as_bytes().to_vec() {
        *is_hashed = true;
    } else {
        panic!("Unsupported signature algorithm");
    }
    sig
}
fn load_message_file<P: AsRef<Path>>(message_file: P) -> Vec<u8>
    where P: std::marker::Copy
{
    let file = OpenOptions::new()
        .read(true)
        .open(message_file)
        .expect("error opening file");
    if file.metadata().unwrap().len() > (1u64 << 30) {
        panic!("File {} is larger than 1G try using -H",
               message_file.as_ref().to_str().unwrap());
    }
    let mut file_buf = BufReader::new(file);
    let mut msg_buf: Vec<u8> = Vec::new();
    file_buf.read_to_end(&mut msg_buf).unwrap();
    msg_buf
}
fn load_and_hash_message_file<P: AsRef<Path>>(message_file: P) -> Vec<u8>
    where P: std::marker::Copy
{
    let file = OpenOptions::new()
        .read(true)
        .open(message_file)
        .expect("error opening file");
    let mut buf_reader = BufReader::new(file);
    let mut buf_chunk = [0u8; 65536];
    let state_sz = unsafe { ffi::crypto_generichash_statebytes() };
    let mut state: Vec<u8> = vec![0;state_sz];
    let ptr_state = state.as_mut_ptr() as *mut ffi::crypto_generichash_state;
    generichash::init(ptr_state).unwrap();
    while buf_reader.read(&mut buf_chunk).unwrap() > 0 {
        generichash::update(ptr_state, &buf_chunk).unwrap();
    }
    generichash::finalize(ptr_state)
        .unwrap()
        .as_ref()
        .to_vec()
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
        
        let sk = sk_load(sk_file).unwrap();

        let _ = sign(sk,
                     pk,
                     sign_action.value_of("sig_file"),
                     sign_action.value_of("message").unwrap(),
                     sign_action.value_of("trusted-comment"),
                     sign_action.value_of("untrusted-comment"),
                     sign_action.is_present("hash"));
    }

    if let Some(verify_action) = args.subcommand_matches("verify") {
        let pk = pk_load(verify_action.value_of("pk_path").unwrap()).unwrap();
        let sig_file = verify_action.value_of("sig_file").unwrap();
        let message_file = verify_action.value_of("file").unwrap();
        let _ = verify(pk, sig_file, message_file, false, false);
    }


}
