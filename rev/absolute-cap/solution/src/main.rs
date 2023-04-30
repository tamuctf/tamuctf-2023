use std::fs::{read_to_string, write};
use std::io;
use std::io::{stdout, Write};
use std::str::FromStr;

fn main() -> Result<(), io::Error> {
    write(
        "/proc/self/timerslack_ns",
        u64::from_be_bytes(*b"imclient").to_string(),
    )?;

    loop {
        let content = u64::from_str(&read_to_string("/proc/self/timerslack_ns")?.trim()).unwrap();
        if content == u64::from_be_bytes(*b"imserver") {
            println!("got a server!");
            break;
        }
    }

    loop {
        write(
            "/proc/self/timerslack_ns",
            u64::from_be_bytes(*b"imready!").to_string(),
        )?;
        loop {
            let content =
                u64::from_str(read_to_string("/proc/self/timerslack_ns")?.trim()).unwrap();
            if content != u64::from_be_bytes(*b"imready!") {
                stdout().write_all(&content.to_be_bytes())?;
                break;
            }
        }
    }
}
