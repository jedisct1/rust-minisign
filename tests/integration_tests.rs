extern crate rsign;

use rsign::*;


fn generate_keypair() -> (PubkeyStruct, SeckeyStruct) {
    let (pk,sk) = gen_keystruct();
}

#[test]
fn sign() {
    let (pk,sk) = generate_keypair();
}