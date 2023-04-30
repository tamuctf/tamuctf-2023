use std::fs::{read_dir, read_to_string, write};
use std::io;
use std::io::ErrorKind;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

const CLIENT_AUTH: u64 = u64::from_be_bytes(*b"imclient");
const CLIENT_DISCONNECT: u64 = u64::from_be_bytes(*b"imdying!");
const CLIENT_READY: u64 = u64::from_be_bytes(*b"imready!");
const SERVER_AUTH: u64 = u64::from_be_bytes(*b"imserver");

pub struct Client {
    target: String,
}

pub struct Server {
    _hidden: (),
}

impl Client {
    pub fn find_server() -> Result<Option<Self>, io::Error> {
        let mut pids = Vec::new();
        for process in read_dir("/proc")? {
            let path = process?.path();
            if let Some(pid) = path
                .file_name()
                .and_then(|filename| filename.to_str())
                .and_then(|filename| u64::from_str(filename).ok())
            {
                pids.push(pid);
            }
        }
        pids.sort_unstable();

        for pid in pids {
            let target = format!("/proc/{pid}/timerslack_ns");
            let mut this = Self { target };
            if this
                .try_read_chunk()
                .map(|chunk| chunk == CLIENT_AUTH)
                .unwrap_or(false)
            {
                write(&this.target, format!("{SERVER_AUTH}"))?;
                return Ok(Some(this));
            }
        }

        Ok(None)
    }

    fn try_read_chunk(&mut self) -> Result<u64, io::Error> {
        Ok(u64::from_str(read_to_string(&self.target)?.trim()).unwrap())
    }

    pub fn wait_until_ready(&mut self) -> Result<(), io::Error> {
        loop {
            let chunk = self.try_read_chunk()?;
            match chunk {
                CLIENT_READY => return Ok(()),
                CLIENT_DISCONNECT => return Err(io::Error::from(ErrorKind::BrokenPipe)),
                _ => sleep(Duration::from_millis(10)),
            }
        }
    }

    pub fn write_msg(&mut self, content: &[u8]) -> Result<(), io::Error> {
        assert!(content.len() < u32::MAX as usize);

        self.wait_until_ready()?;

        write(&self.target, format!("{}", content.len()))?;

        let chunks = content.chunks_exact(core::mem::size_of::<u32>());

        let remainder = chunks.remainder();

        for chunk in chunks {
            self.wait_until_ready()?;
            let num =
                u32::from_be_bytes(<[u8; core::mem::size_of::<u32>()]>::try_from(chunk).unwrap());
            write(&self.target, format!("{num}"))?;
        }

        if !remainder.is_empty() {
            self.wait_until_ready()?;
            let mut chunk = Vec::from(remainder);
            chunk.resize(core::mem::size_of::<u32>(), 0);

            let num =
                u32::from_be_bytes(<[u8; core::mem::size_of::<u32>()]>::try_from(chunk).unwrap());
            write(&self.target, format!("{num}"))?;
        }

        Ok(())
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

impl Server {
    pub fn wait_for_connection() -> Result<Self, io::Error> {
        write("/proc/self/timerslack_ns", format!("{CLIENT_AUTH}"))?;

        loop {
            if u64::from_str(read_to_string("/proc/self/timerslack_ns")?.trim()).unwrap()
                == SERVER_AUTH
            {
                break Ok(Self { _hidden: () });
            }
        }
    }

    fn next_server_chunk(&mut self) -> Result<u32, io::Error> {
        write("/proc/self/timerslack_ns", format!("{CLIENT_READY}"))?;
        loop {
            let last = u64::from_str(read_to_string("/proc/self/timerslack_ns")?.trim()).unwrap();
            if last != CLIENT_READY {
                break Ok(last as u32);
            }
        }
    }

    pub fn read_msg(&mut self) -> Result<Vec<u8>, io::Error> {
        let size = self.next_server_chunk()? as usize;
        let mut buf = Vec::with_capacity(size + 3);

        while buf.len() < size {
            buf.extend_from_slice(&self.next_server_chunk()?.to_be_bytes());
        }

        buf.truncate(size);

        Ok(buf)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        write("/proc/self/timerslack_ns", format!("{CLIENT_DISCONNECT}")).unwrap();
    }
}
