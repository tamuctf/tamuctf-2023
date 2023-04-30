use std::error::Error;
use std::process::{Command, Stdio};

fn main() -> Result<(), Box<dyn Error>> {
    let mut server = Command::new("/server")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut friend = Command::new("/friend")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    friend.wait()?;
    server.wait()?;

    Ok(())
}
