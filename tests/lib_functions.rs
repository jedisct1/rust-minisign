#[macro_use]
extern crate unwrap;
extern crate base64;
extern crate rsign;
extern crate libsodium_sys as ffi;

use rsign::*;

use std::process::{Command, Stdio};
use std::io::BufWriter;

const PK_UNT_COMMENT: &'static str = "untrusted comment: rsign public key: C8842CB5A2989BE7";
const PK: &[u8] = b"RWTnm5iitSyEyKyaniIFQabFeKj0EScabgDrJM8wsCBzg5jg9dFiWXCi";
const SK_UNT_COMMENT: &'static str = "untrusted comment: rsign encrypted secret key";
const SK: &[u8] = b"RWRTY0Iyvpg1Je/NLfXYyY9pNMOu6vU1vxGyds3DysvAZ3jvu2oAAAACAAAAAAAAAEAAAAAAuj+eiMbdoT8D5CWnfkVPsrwOOzPs20czHYYJ8cgKX5uvt8hMrwbfbYTEhXJUd4EEUr2yWM4SuaymXZ+8uM2OL7va5HCp33S6HgJqiMdL1O4qQLcwIT2R6/oRsljKAXwSktuTiKV3SVw=";
const MSG: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi a velit at nisi molestie elementum at quis nisi. Quisque vestibulum libero a orci rhoncus elementum. Donec placerat dapibus cursus. Phasellus neque ex, pretium eget tellus tempus, tristique suscipit erat. Nulla volutpat luctus nunc, eu malesuada lacus rutrum eu. Sed a ipsum vel ex cursus condimentum aliquet sit amet nisi. Pellentesque felis sapien, hendrerit ac eleifend eget, rhoncus non tortor. Fusce elementum, velit non ullamcorper luctus, odio sapien consequat augue, vitae condimentum mi enim ac nunc. Ut facilisis eleifend arcu. Ut tincidunt ultrices nibh quis tristique. Nullam sit amet purus accumsan, interdum risus ac, lacinia nulla.\n";

const SIG: &[u8] = b"untrusted comment: signature from rsign secret key\nRWS6P56Ixt2hP7LjbYHZ+P1UjHIAv6q1hLkIU8XnG8jHbbb/4RJFRf80jDESY/nlcVdL0x1bhXt0Z4/jzXmbjj6IMpZEdPs3GAk=\ntrusted comment: timestamp:1505779123\tfile:testfile.txt\nQVXAXwZVjwxz5At8GU6mKC8f1Fl5u9No5jCjYpYRxe/OYY/kufZIz4ji9VzZTk8V/DtA61+TT7ZKVG/OJrfnAw==";

#[test]
fn signing_without_pk() {
    let sk_bytes = unwrap!(base64::decode(SK));
    let sk = unwrap!(SeckeyStruct::from(&sk_bytes[..]));
    let pk = None;
    let mut sig_buf = Vec::with_capacity(SIG.len());
    let message = MSG;
    let hashed = false;
    let trusted_comment: &'static str = "timestamp:1505779123	file:testfile.txt";
    let untrusted_comment: &'static str = "untrusted comment: signature from rsign secret key";
   
    assert!(sign(sk, pk, &mut sig_buf , message, hashed, trusted_comment, untrusted_comment).is_ok());
    assert_eq!(unwrap!(String::from_utf8(sig_buf)).trim(), unwrap!(String::from_utf8(SIG.to_vec())) );
}

/* #[test]
fn signing_with_pk() {
    let sk_bytes = unwrap!(base64::decode(SK));
    let sk = unwrap!(SeckeyStruct::from(&sk_bytes[..]));
    let pk_bytes = unwrap!(base64::decode(PK));
    let pk = unwrap!(PubkeyStruct::from(&pk_bytes[..]));
    let mut sig_buf = Vec::with_capacity(SIG.len());
    let message = MSG;
    let hashed = false;
    let trusted_comment: &'static str = "trusted comment: timestamp:1505779123	file:testfile.txt";
    let untrusted_comment: &'static str = "untrusted comment: signature from rsign secret key";
   
    assert!(sign(sk, Some(pk), &mut sig_buf , message, hashed, trusted_comment, untrusted_comment).is_ok());
    assert_eq!(unwrap!(String::from_utf8(sig_buf)).trim(), unwrap!(String::from_utf8(SIG.to_vec())) );
}

fn hash_me(data: &[u8]) -> Vec<u8> {
        let state_sz = unsafe { ffi::crypto_generichash_statebytes() };
        let mut state: Vec<u8> = vec![0;state_sz];
        let ptr_state = state.as_mut_ptr() as *mut ffi::crypto_generichash_state;
        unwrap!(generichash::init(ptr_state));
        unwrap!(generichash::update(ptr_state, data));
        let h = unwrap!(generichash::finalize(ptr_state));
        Vec::from(&h[..])
}

#[test]
fn signing_hashed_message() {
    let sk_bytes = unwrap!(base64::decode(SK));
    let sk = unwrap!(SeckeyStruct::from(&sk_bytes[..]));
    let pk_bytes = unwrap!(base64::decode(PK));
    let pk = unwrap!(PubkeyStruct::from(&pk_bytes[..]));
    let mut sig_buf = Vec::with_capacity(SIG.len());
    let message = hash_me(MSG);
    let hashed = true;
    let trusted_comment: &'static str = "timestamp:1505779123	file:testfile.txt";
    let untrusted_comment: &'static str = "untrusted comment: signature from rsign secret key";
   
    assert!(sign(sk, Some(pk), &mut sig_buf , &message[..], hashed, trusted_comment, untrusted_comment).is_ok());
} */
