use reqwest::cookie::Jar;
use reqwest::multipart::{Form, Part};
use reqwest::{Body, Url};
use std::sync::Arc;
use tokio::fs::File;
use tokio::net::{TcpListener, UnixStream};
use tokio_util::codec::{BytesCodec, FramedRead};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::var("SERVER_ADDR")
        .expect("Couldn't find an appropriate server address; did you set SERVER_ADDR?");

    let server = TcpListener::bind("localhost:0").await?;
    let mut actual = UnixStream::connect(addr).await?;
    let port = server.local_addr()?.port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = server.accept().await {
            tokio::io::copy_bidirectional(&mut stream, &mut actual)
                .await
                .unwrap();
        }
    });

    let addr = format!("http://localhost:{port}");

    let file = File::open("/root/flag.txt").await?;

    let stream = FramedRead::new(file, BytesCodec::new());
    let part = Part::stream(Body::wrap_stream(stream)).file_name("flag.txt");

    let cookies = Jar::default();
    cookies.add_cookie_str(
        "whoami=supersecretspecialcookiec5e981ca4e45fffbfa962b3ce7e8396c",
        &Url::parse(&addr).unwrap(),
    );

    let client = reqwest::Client::builder()
        .cookie_provider(Arc::new(cookies))
        .build()?;
    let resp = client
        .post(addr)
        .multipart(Form::new().part("flag.txt", part))
        .send()
        .await?;

    println!("{}", resp.text().await?);

    Ok(())
}
