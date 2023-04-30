#![cfg_attr(not(feature = "std"), no_std)]
#![feature(iterator_try_collect)]
#![cfg_attr(feature = "std", feature(io_error_more))]

pub mod messages;
#[cfg(feature = "stamps")]
pub mod stamps;

extern crate alloc;

#[cfg(feature = "std")]
use std::io::{ErrorKind, Read};

use alloc::vec::Vec;
use postcard::Error;
use serde::{Deserialize, Serialize};

pub const MSG_MAGIC: &[u8] = b"COURIERM";

#[derive(Debug)]
pub enum ReadMsgError {
    NotYetDone,
    #[cfg(feature = "std")]
    IoError(std::io::Error),
    PostcardError(Error),
    MessageTooLong,
}

impl From<Error> for ReadMsgError {
    fn from(value: Error) -> Self {
        ReadMsgError::PostcardError(value)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ReadMsgError {
    fn from(value: std::io::Error) -> Self {
        ReadMsgError::IoError(value)
    }
}

pub fn try_read_msg<M: for<'a> Deserialize<'a>, const MAX_SIZE: u16, const CLEAR_ON_DESER: bool>(
    buf: &mut Vec<u8>,
) -> Result<M, ReadMsgError> {
    if buf.len() >= MSG_MAGIC.len() + core::mem::size_of::<u16>() {
        let mut len_buf = [0u8; core::mem::size_of::<u16>()];
        buf.iter()
            .copied()
            .skip(MSG_MAGIC.len())
            .take(core::mem::size_of::<u16>())
            .zip(&mut len_buf)
            .for_each(|(b, e)| *e = b);
        let msg_len = u16::from_be_bytes(len_buf);
        if msg_len > MAX_SIZE {
            #[cfg(feature = "semihosted-debug")]
            cortex_m_semihosting::heprintln!(
                "message would have exceeded max length: {} / {}",
                msg_len,
                MAX_SIZE
            );

            buf.clear();
            return Err(ReadMsgError::MessageTooLong);
        }

        #[cfg(feature = "semihosted-debug")]
        cortex_m_semihosting::heprintln!(
            "attempting read of a message with length: {} / {}",
            buf.len(),
            MSG_MAGIC.len() + core::mem::size_of::<u16>() + msg_len as usize
        );

        if buf.len() == MSG_MAGIC.len() + core::mem::size_of::<u16>() + msg_len as usize {
            #[cfg(feature = "semihosted-debug")]
            cortex_m_semihosting::heprintln!("reading a message with length: {}", msg_len);

            let value =
                postcard::from_bytes(&buf[(MSG_MAGIC.len() + core::mem::size_of::<u16>())..])?;
            if CLEAR_ON_DESER {
                buf.clear();
            }
            return Ok(value);
        }
    } else if buf.len() <= MSG_MAGIC.len() {
        if let Some(last) = buf.last().copied() {
            if last != MSG_MAGIC[buf.len() - 1] {
                #[cfg(feature = "semihosted-debug")]
                cortex_m_semihosting::heprintln!("failed the magic check: {:?}", buf);

                buf.clear();
                buf.push(last); // we might actually be handling the next valid input!
            }
        }
    }

    Err(ReadMsgError::NotYetDone)
}

#[cfg(feature = "std")]
pub fn read_msg<R: Read, M: for<'a> Deserialize<'a>, const MAX_SIZE: u16>(
    reader: &mut R,
) -> Result<M, ReadMsgError> {
    let mut bytes = reader.bytes();

    {
        let mut magic = heapless::Vec::<_, { MSG_MAGIC.len() }>::new();
        loop {
            if let Some(last) = magic.last().copied() {
                if last != MSG_MAGIC[magic.len() - 1] {
                    magic.clear();
                    magic.push(last).unwrap();
                    continue;
                }
            }
            if magic.len() == MSG_MAGIC.len() {
                break;
            }
            magic.push(bytes.next().unwrap()?).unwrap();
        }
    }

    let mut len_buf = [0u8; core::mem::size_of::<u16>()];
    (&mut bytes)
        .take(core::mem::size_of::<u16>())
        .zip(&mut len_buf)
        .try_for_each(|(b, e)| {
            *e = b?;
            Ok::<_, std::io::Error>(())
        })?;
    let msg_len = u16::from_be_bytes(len_buf);
    if msg_len > MAX_SIZE {
        Err(std::io::Error::from(ErrorKind::FileTooLarge).into())
    } else {
        Ok(postcard::from_bytes(
            &bytes.take(msg_len as usize).try_collect::<Vec<_>>()?,
        )?)
    }
}

pub fn into_msg<M: Serialize>(value: M) -> impl Iterator<Item = u8> + Send {
    let serialised = postcard::to_allocvec(&value).unwrap();
    assert!(serialised.len() <= u16::MAX as usize);
    MSG_MAGIC
        .iter()
        .copied()
        .chain((serialised.len() as u16).to_be_bytes())
        .chain(serialised)
}
