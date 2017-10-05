#[macro_use]
extern crate unwrap;

use std::process::{Command, Stdio};
use std::io::Write;
use std::fs::remove_file;
use std::path::Path;

/* // https://stackoverflow.com/questions/29963449/golang-like-defer-in-rust
struct ScopeCall<F: FnOnce()> {
    c: Option<F>
}
impl<F: FnOnce()> Drop for ScopeCall<F> {
    fn drop(&mut self) {
        self.c.take().unwrap()()
    }
}

macro_rules! expr { ($e: expr) => { $e } } // tt hack
macro_rules! defer {
    ($($data: tt)*) => (
        let _scope_call = ScopeCall {
            c: Some(|| -> () { expr!({ $($data)* }) })
        };
    )
}
*/
macro_rules! t {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {}", stringify!($e), e),
    })
} 

fn get_test_dir() -> String {
    use std::env;
    let mut current_path = unwrap!(env::current_dir());
    println!("{:?}", current_path);
    current_path.push("target/debug/test/");
    unwrap!(current_path.into_os_string().into_string())
}

fn remove_if_exists<P: AsRef<Path>>(file: P) {
    if file.as_ref().exists() {
        t!(remove_file(file));
    }
}

use std::io;
fn gen_test_file<P: AsRef<Path>>(path: Option<P>) -> Result<(), io::Error> {
    use std::fs::File;
   

    const TEXT: &'static str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi a velit at nisi molestie elementum at quis nisi. Quisque vestibulum libero a orci rhoncus elementum. Donec placerat dapibus cursus. Phasellus neque ex, pretium eget tellus tempus, tristique suscipit erat. Nulla volutpat luctus nunc, eu malesuada lacus rutrum eu. Sed a ipsum vel ex cursus condimentum aliquet sit amet nisi. Pellentesque felis sapien, hendrerit ac eleifend eget, rhoncus non tortor. Fusce elementum, velit non ullamcorper luctus, odio sapien consequat augue, vitae condimentum mi enim ac nunc. Ut facilisis eleifend arcu. Ut tincidunt ultrices nibh quis tristique. Nullam sit amet purus accumsan, interdum risus ac, lacinia nulla.";
    const TEST_FILE_NAME: &'static str = "testfile.txt";
    let file_path = match path {
        Some(path) => {
            remove_if_exists(&path);
            path.as_ref().to_str().unwrap().to_owned()
        },
        None => TEST_FILE_NAME.to_owned(),
    };
    File::create(file_path)
        .and_then(|mut file| writeln!(file, "{}", TEXT))?;
    Ok(())
}

#[test]
fn generate() {
    use std::fs;
    use std::env;
    use std::path::PathBuf;
    let mut rsign_exe = unwrap!(env::current_dir());
    rsign_exe.push("target/debug/rsign");
    let test_dir = get_test_dir();
    unwrap!(fs::create_dir_all(&test_dir));

    let sk_path = PathBuf::from(test_dir.clone() + "rsign.key");
    let pk_path = PathBuf::from(test_dir.clone() + "rsign.pub");
    remove_if_exists(&sk_path);
    remove_if_exists(&pk_path);

    let mut child = Command::new(rsign_exe)
        .args(vec!["generate", "-srsign.key", "-prsign.pub"])
        .current_dir(&test_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute rsign");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(b"test")
            .expect("failed to write to stdin");
        stdin.write(b"\n").unwrap();
        stdin
            .write_all(b"test")
            .expect("failed to write to stdin, second time");
        stdin.write(b"\n").unwrap();
    }

    let _output = child
        .wait_with_output()
        .expect("failed to wait on child");

    assert!(pk_path.exists() && sk_path.exists());
}
#[test]
fn sign() {
    use std::fs;
    use std::path::PathBuf;
    use std::env;

    let mut rsign_exe = unwrap!(env::current_dir());
    rsign_exe.push("target/debug/rsign");
    let test_dir = get_test_dir();
    let file_to_sign = test_dir.clone() + "testfile.txt";
    unwrap!(fs::create_dir_all(&test_dir));
    assert!(gen_test_file(Some(file_to_sign)).is_ok());
    let mut child = Command::new(rsign_exe)
        .current_dir(&test_dir)
        .args(vec!["sign", "testfile.txt", "-srsign.key", "-prsign.pub"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute rsign");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(b"test")
            .expect("failed to write to stdin");
        stdin.write(b"\n").unwrap();
    }
    let signature_path = test_dir + "testfile.txt.rsign";
    let signature_file = PathBuf::from(signature_path);
    let status = child.wait().unwrap();
    assert!(signature_file.exists());

    assert!(status.success());
}
#[test]
fn sign_with_wrong_pass() {
    use std::fs;
    use std::env;
    
    let mut rsign_exe = unwrap!(env::current_dir());
    rsign_exe.push("target/debug/rsign");
    let test_dir = get_test_dir();
    let file_to_sign = test_dir.clone() + "testfile.txt";
    unwrap!(fs::create_dir_all(&test_dir));
    assert!(gen_test_file(Some(file_to_sign)).is_ok());
    let mut child = Command::new(rsign_exe)
        .current_dir(&test_dir)
        .args(vec!["sign", "testfile.txt", "-srsign.key", "-prsign.pub"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute rsign");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(b"wrong_password")
            .expect("failed to write to stdin");
        stdin.write(b"\n").unwrap();
    }
    
    let status = unwrap!(child.wait());
    assert!(!status.success());
}

#[test]
fn verify_without_pk() {
    use std::env;

    let mut rsign_exe = unwrap!(env::current_dir());
    rsign_exe.push("target/debug/rsign");
    let test_dir = get_test_dir();

    let mut child = Command::new(rsign_exe)
        .current_dir(test_dir)
        .args(vec!["verify", "testfile.txt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute rsign");

    {
        let _stdin = child.stdin.as_mut().expect("failed to get stdin");

    }
    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn verify_with_pk_file() {
    use std::env;

    let mut rsign_exe = unwrap!(env::current_dir());
    rsign_exe.push("target/debug/rsign");
    let test_dir = get_test_dir();

    let mut child = Command::new(rsign_exe)
        .current_dir(test_dir)
        .args(vec!["verify", "testfile.txt", "-prsign.pub"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute rsign");

    {
        let _stdin = child.stdin.as_mut().expect("failed to get stdin");

    }
    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn verify_with_pk_string() {
    use std::env;
    use std::fs::File;
    let mut rsign_exe = unwrap!(env::current_dir());
    rsign_exe.push("target/debug/rsign");
    let test_dir = get_test_dir();
    let rsign_pk_path = test_dir.clone() + "rsign.pub";
    unwrap!(File::open(rsign_pk_path)
        .and_then(|file| {
            use std::io::{BufReader, BufRead};
            let mut pk_buf = BufReader::new(file);
            let mut _comment = String::new();
            try!(pk_buf.read_line(&mut _comment));
            let mut pk_string = String::new();
            pk_buf.read_line(&mut pk_string)
                .and_then(|_|{
                    let mut child = Command::new(rsign_exe)
                        .current_dir(&test_dir)
                        .args(vec!["verify", "testfile.txt", "-P", pk_string.trim()])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .spawn()
                        .expect("failed to execute rsign");
                        {
                            let _stdin = child.stdin.as_mut().expect("failed to get stdin");

                        }
                        let status = child.wait().unwrap();
                        assert!(status.success());
                        Ok(())
                })}
                ));
    
}