use proto::Client;
use std::convert::Infallible;
use std::fs::read_to_string;
use std::io;
use std::thread::sleep;
use std::time::Duration;

fn interact(mut client: Client) -> Result<Infallible, io::Error> {
    loop {
        client.wait_until_ready()?;
        client.write_msg(read_to_string("flag.txt")?.as_bytes())?;
    }
}

fn main() -> Result<(), io::Error> {
    loop {
        if let Ok(Some(client)) = Client::find_server() {
            println!("Found a server!: {}", client.target());
            let e = interact(client).unwrap_err();
            println!("Lost our server ({e}), beginning search...");
        }
        sleep(Duration::from_millis(500));
    }
}
