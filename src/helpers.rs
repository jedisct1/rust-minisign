use crate::constants::*;
use crate::errors::*;
use scrypt::ScryptParams;
use std::cmp;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(windows, unix))]
use rpassword::prompt_password_stdout;

#[cfg(not(any(windows, unix)))]
fn prompt_password_stdout(prompt: &str) -> Result<String> {
    use std::io::{stdin, stdout, Write};

    stdout().write_all(prompt.as_bytes())?;
    stdout().flush()?;
    let mut password = String::new();
    stdin().read_line(&mut password)?;
    Ok(password)
}

pub fn store_u64_le(x: u64) -> [u8; 8] {
    let b1: u8 = (x & 0xff) as u8;
    let b2: u8 = ((x >> 8) & 0xff) as u8;
    let b3: u8 = ((x >> 16) & 0xff) as u8;
    let b4: u8 = ((x >> 24) & 0xff) as u8;
    let b5: u8 = ((x >> 32) & 0xff) as u8;
    let b6: u8 = ((x >> 40) & 0xff) as u8;
    let b7: u8 = ((x >> 48) & 0xff) as u8;
    let b8: u8 = ((x >> 56) & 0xff) as u8;
    [b1, b2, b3, b4, b5, b6, b7, b8]
}

#[allow(clippy::cast_lossless)]
pub fn load_u64_le(x: &[u8]) -> u64 {
    (x[0] as u64)
        | (x[1] as u64) << 8
        | (x[2] as u64) << 16
        | (x[3] as u64) << 24
        | (x[4] as u64) << 32
        | (x[5] as u64) << 40
        | (x[6] as u64) << 48
        | (x[7] as u64) << 56
}

pub fn raw_scrypt_params(memlimit: usize, opslimit: u64, n_log2_max: u8) -> Result<ScryptParams> {
    let opslimit = cmp::max(32768, opslimit);
    let mut n_log2 = 1u8;
    let r = 8u32;
    let p;
    if opslimit < (memlimit / 32) as u64 {
        p = 1;
        let maxn = opslimit / (u64::from(r) * 4);
        while n_log2 < 63 {
            if 1u64 << n_log2 > maxn / 2 {
                break;
            }
            n_log2 += 1;
        }
    } else {
        let maxn = memlimit as u64 / (u64::from(r) * 128);
        while n_log2 < 63 {
            if 1u64 << n_log2 > maxn / 2 {
                break;
            }
            n_log2 += 1;
        }
        let maxrp = cmp::min(
            0x3fff_ffff as u32,
            ((opslimit / 4) / (1u64 << n_log2)) as u32,
        );
        p = maxrp / r;
    }
    if n_log2 > n_log2_max {
        return Err(PError::new(ErrorKind::KDF, "scrypt parameters too high"));
    }
    ScryptParams::new(n_log2, r, p).map_err(Into::into)
}

pub fn get_password(prompt: &str) -> Result<String> {
    let pwd = prompt_password_stdout(prompt)?;
    if pwd.is_empty() {
        println!("<empty>");
        Ok(pwd)
    } else if pwd.len() > PASSWORD_MAXBYTES {
        Err(PError::new(
            ErrorKind::Misc,
            "passphrase can't exceed 1024 bytes length",
        ))
    } else {
        Ok(pwd)
    }
}

pub fn unix_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("system clock is incorrect");
    since_the_epoch.as_secs()
}
