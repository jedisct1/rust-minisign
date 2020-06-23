/// The default untrusted comment.
pub const DEFAULT_COMMENT: &str = "signature from rsign secret key";

/// The default environment variable for the directory of the `rsign` tool.
pub const SIG_DEFAULT_CONFIG_DIR_ENV_VAR: &str = "RSIGN_CONFIG_DIR";

/// The default configuration directory of the `rsign` tool.
pub const SIG_DEFAULT_CONFIG_DIR: &str = ".rsign";

/// The default file name for the public key.
pub const SIG_DEFAULT_PKFILE: &str = "rsign.pub";

/// The default file name for the secret key.
pub const SIG_DEFAULT_SKFILE: &str = "rsign.key";

/// The default suffix for signatures.
pub const SIG_SUFFIX: &str = ".minisig";

pub(crate) const CHK_ALG: [u8; 2] = *b"B2";
pub(crate) const CHK_BYTES: usize = 32;
pub(crate) const COMMENT_PREFIX: &str = "untrusted comment: ";
pub(crate) const KDF_ALG: [u8; 2] = *b"Sc";
pub(crate) const KDF_SALTBYTES: usize = 32;
pub(crate) const KEYNUM_BYTES: usize = 8;
pub(crate) const MEMLIMIT: usize = 33_554_432;
pub(crate) const OPSLIMIT: u64 = 1_048_576;
pub(crate) const MEMLIMIT_MAX: usize = 1_073_741_824;
pub(crate) const N_LOG2_MAX: u8 = 20;
pub(crate) const PASSWORD_MAXBYTES: usize = 1024;
pub(crate) const PK_B64_ENCODED_LEN: usize = 56;
pub(crate) const PREHASH_BYTES: usize = 64;
pub(crate) const PUBLICKEY_BYTES: usize = 32;
pub(crate) const SECRETKEY_BYTES: usize = 64;
pub(crate) const SECRETKEY_DEFAULT_COMMENT: &str = "rsign encrypted secret key";
pub(crate) const SIGALG_PREHASHED: [u8; 2] = *b"ED";
pub(crate) const SIGALG: [u8; 2] = *b"Ed";
pub(crate) const SIGNATURE_BYTES: usize = 64;
pub(crate) const TRUSTED_COMMENT_PREFIX_LEN: usize = 17;
pub(crate) const TRUSTED_COMMENT_PREFIX: &str = "trusted comment: ";
pub(crate) const TWOBYTES: usize = 2;
