    #[test]
    fn byte_array_store() {
        use crate::store_u64_le;

        assert_eq!([0xFF, 0, 0, 0, 0, 0, 0, 0], store_u64_le(0xFF));
    }
    #[test]
    fn byte_array_load() {
        use crate::load_u64_le;

        assert_eq!(255, load_u64_le(&[0xFF, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn pk_key_struct_conversion() {
        use crate::generate_unencrypted_keypair;
        use crate::PublicKey;

        let (pk, _) = generate_unencrypted_keypair().unwrap();
        assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
    }
    #[test]
    fn sk_key_struct_conversion() {
        use crate::generate_unencrypted_keypair;
        use crate::SecretKey;

        let (_, sk) = generate_unencrypted_keypair().unwrap();
        assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    }

    #[test]
    fn xor_keynum() {
        use crate::generate_unencrypted_keypair;
        use rand::{thread_rng, RngCore};

        let (_, mut sk) = generate_unencrypted_keypair().unwrap();
        let mut rng = thread_rng();
        let mut key = vec![0u8; sk.keynum_sk.len()];
        rng.fill_bytes(&mut key);
        let original_keynum = sk.keynum_sk.clone();
        sk.xor_keynum(&key);
        assert_ne!(original_keynum, sk.keynum_sk);
        sk.xor_keynum(&key);
        assert_eq!(original_keynum, sk.keynum_sk);
    }
    #[test]
    fn sk_checksum() {
        use crate::generate_unencrypted_keypair;

        let (_, mut sk) = generate_unencrypted_keypair().unwrap();
        assert!(sk.write_checksum().is_ok());
        assert_eq!(sk.keynum_sk.chk.to_vec(), sk.read_checksum().unwrap());
    }