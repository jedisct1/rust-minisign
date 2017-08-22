extern crate rsign;
extern crate sodiumoxide;
extern crate base64;
extern crate libsodium_sys as ffi;
extern crate rpassword;

use rsign::parse_args::parse_args;
use rsign::{SeckeyStruct,PubkeyStruct};

use sodiumoxide::crypto::sign::{PublicKey, SecretKey, Signature};
use sodiumoxide::crypto::pwhash;

use std::fmt;
use std::io::prelude::*;
use std::io::{self, BufWriter, BufReader, Stdout};
use std::fs::{OpenOptions, File};
use std::path::Path;
use std::process;

fn create_file<P: AsRef<Path>>(path_sk: P, path_pk: P) -> Result<(BufWriter<File>, BufWriter<File>), ()> {
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
                                                       -> Result<(),io::Error> {
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
    writeln!(pk_buf, "{}",base64::encode(pk_struct_bytes.as_slice()))?;
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

fn sk_load(sk_path: AsRef<Path>) -> SeckeyStruct {
    let sk_file = OpenOptions::new()
        .read(true)
        .open(sk_path)
        .unwrap();
    let sk_buf = BufReader::new(sk_file);
    sk_buf.read_line(String::new());
    let mut bytes_buf:Vec<u8> = Vec::new();
    sk_buf.read_to_end(bytes_buf).unwrap();
    SeckeyStruct {
        sig_alg: 
        kdf_alg: 
        chk_alg: 
        kdf_salt: 
        kdf_opslimit_le: OPSLIMIT_SENSITIVE,
        kdf_memlimit_le: MEMLIMIT_SENSITIVE,
        keynum_sk: KeynumSK {
            keynum: key_vec.clone(),
            sk: sk_vec,
            chk: Vec::with_capacity(BYTES),
        },
    }
}

fn sign(sk_key: &mut SeckeyStruct, pk_key: &mut PubkeyStruct, message_file: BufReader<File>, sig_file: BufWriter<File>,
trusted_comment: Option<AsRef<String>>, untrusted_comment: Option<AsRef<String>>, hashed: bool) 
{

}

fn main() {
    let args = parse_args();
    sodiumoxide::init();

    if let Some(generate_action) = args.subcommand_matches("generate") {
        //TODO: add parent folder to sk_file_path
       let _ = generate_keys(generate_action.value_of("pk_file_path").unwrap(), 
            generate_action.value_of("sk_file_path").unwrap(),
            generate_action.value_of("comment"),
            generate_action.is_present("force"));
        
    }

    if let Some(sign_action) = args.subcommand_matches("sign") {
        let sk_file = sign_action.value_of("sk_path").unwrap();
        let sk_struct = sk_load(sk_file);
        let _ = sign(,sign_action.value_of("trusted-comment"),sign_action.value_of("untrusted-comment"),sign_action.is_present("hash"));
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
