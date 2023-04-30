use reqwest::cookie::Jar;
use reqwest::multipart::{Form, Part};
use reqwest::{Body, Url};
use std::sync::Arc;
use tokio::io::stdin;
use tokio_util::codec::{BytesCodec, FramedRead};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = format!("http://localhost:8937");

    let stream = FramedRead::new(stdin(), BytesCodec::new());
    let part = Part::stream(Body::wrap_stream(stream)).file_name("flag.txt");

    let cookies = Jar::default();
    cookies.add_cookie_str("whoami=lmao", &Url::parse(&addr).unwrap());

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
