
use std::process::{Command, Stdio};
use std::io::Write;
use std::fs::remove_file;
use std::path::Path;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {}", stringify!($e), e),
    })
}

fn remove_if_exists<P: AsRef<Path>>(file: P) {
    if file.as_ref().exists() {
        t!(remove_file(file));
    }
}

#[test]
fn generate() {
    remove_if_exists("rsign.key");
    remove_if_exists("rsign.pub");
    let mut child = Command::new("./target/debug/rsign")
        .args(vec!["generate", "-srsign.key", "-prsign.pub"])
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

    assert!(Path::new("rsign.key").exists() && Path::new("rsign.pub").exists());
}
#[test]
fn sign() {
    use std::fs::File;
    use std::io; 
    const TEXT: &'static str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi a velit at nisi molestie elementum at quis nisi. Quisque vestibulum libero a orci rhoncus elementum. Donec placerat dapibus cursus. Phasellus neque ex, pretium eget tellus tempus, tristique suscipit erat. Nulla volutpat luctus nunc, eu malesuada lacus rutrum eu. Sed a ipsum vel ex cursus condimentum aliquet sit amet nisi. Pellentesque felis sapien, hendrerit ac eleifend eget, rhoncus non tortor. Fusce elementum, velit non ullamcorper luctus, odio sapien consequat augue, vitae condimentum mi enim ac nunc. Ut facilisis eleifend arcu. Ut tincidunt ultrices nibh quis tristique. Nullam sit amet purus accumsan, interdum risus ac, lacinia nulla.";
    const TEST_FILE_NAME: &'static str = "testfile.txt";

    fn gen_test_file() -> Result<(), io::Error> {
        File::create(TEST_FILE_NAME).and_then(|mut file| writeln!(file, "{}", TEXT))

    }
    assert!(gen_test_file().is_ok());
    let mut child = Command::new("./target/debug/rsign")
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

    let status = child.wait().unwrap();
    assert!(Path::new("testfile.txt.rsign").exists());
    assert!(status.success());
}

#[test]
fn verify() {
    let mut child = Command::new("./target/debug/rsign")
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