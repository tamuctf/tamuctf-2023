use axum::{extract::Multipart, response::Html, routing::get, Router, Server};
use clap::Parser;
use color_eyre::eyre::{bail, eyre, Result};
use nix::fcntl::{fcntl, FcntlArg, SealFlag};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use std::ffi::CString;
use std::fs::Permissions;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

#[derive(Parser)]
struct Args {
    #[clap(long)]
    /// Path to flag.
    flag: PathBuf,
    #[clap(long)]
    /// Path to reference stdout.
    ref_stdout: PathBuf,
    #[clap(long)]
    /// Path to reference ELF.
    ref_elf: PathBuf,
    #[clap(long)]
    /// Number of byte diffs.
    diffs: usize,
    #[clap(long)]
    /// Port to listen on.
    port: u16,
}

struct AppState {
    diffs: usize,
    flag: String,
    ref_stdout: Vec<u8>,
    ref_elf: Vec<u8>,
}

impl AppState {
    fn verify_upload(&self, upload: &[u8]) -> bool {
        self.ref_elf
            .iter()
            .zip(upload.iter())
            .filter(|(&a, &b)| a != b)
            .count()
            == self.diffs
    }
}

async fn capture(child: &mut Child) -> Result<Vec<u8>> {
    let mut s = Vec::with_capacity(1024);
    child.stdout.as_mut().unwrap().read_to_end(&mut s).await?;
    child.wait().await?;
    Ok(s)
}

async fn create_memfd(bytes: &[u8]) -> Result<(File, String)> {
    let memfd = memfd_create(
        CString::new("")?.as_c_str(),
        MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING,
    )?;

    let mut file = unsafe { File::from_raw_fd(memfd) };
    file.write_all(bytes).await?;

    file.set_permissions(Permissions::from_mode(0o555)).await?;
    fcntl(memfd, FcntlArg::F_ADD_SEALS(SealFlag::all()))?;

    Ok((file, format!("/proc/self/fd/{memfd}")))
}

async fn exec(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let mut child = Command::new(path.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;

    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(1)) => {
            child.kill().await?;
            bail!("exceeded maximum timeout length")
        },
        stdout = capture(&mut child) => {
            stdout
        },
    }
}

async fn sandbox(elf: &[u8]) -> Result<Vec<u8>> {
    let (fd, path) = create_memfd(elf).await?;
    let res = exec(&path).await;
    drop(fd);
    res
}

async fn handler(multipart: &mut Multipart, state: Arc<AppState>) -> Result<String> {
    let f = multipart
        .next_field()
        .await?
        .ok_or_else(|| eyre!("missing field"))?;
    let bytes = f.bytes().await?;

    let feedback = if state.verify_upload(&bytes) && sandbox(&bytes).await? == state.ref_stdout {
        state.flag.clone()
    } else {
        "incorrect".to_string()
    };
    Ok(feedback)
}

async fn upload(mut multipart: Multipart, state: Arc<AppState>) -> String {
    handler(&mut multipart, state).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        "something went wrong".to_string()
    })
}

async fn hello() -> Html<&'static str> {
    Html(
        r#"
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Eyepatch</title>
    </head>
    <body>
        <form method="post" enctype="multipart/form-data" id="upload">
            <div>
                <label for="file">Choose file to upload</label>
                <input type="file" id="file" name="file" multiple />
            </div>
            <div>
                <button type="submit">Submit</button>
            </div>
        </form>
    </body>
</html>
"#,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        port,
        flag,
        ref_stdout,
        diffs,
        ref_elf,
    } = Args::parse();
    let state = Arc::new(AppState {
        diffs,
        flag: tokio::fs::read_to_string(&flag).await?,
        ref_stdout: tokio::fs::read(&ref_stdout).await?,
        ref_elf: tokio::fs::read(&ref_elf).await?,
    });
    let app = Router::new().route(
        "/",
        get(hello).post({
            let state = Arc::clone(&state);
            move |m| upload(m, state)
        }),
    );
    Server::bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
