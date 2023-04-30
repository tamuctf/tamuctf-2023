use crate::messages::{StampRequiredPackage, StampedPackage};
use hmac::digest::{FixedOutput, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub type StampHmac = Hmac<Sha256>;

#[derive(Debug)]
pub enum StampError {
    InvalidCtr,
    InvalidStamp,
    Postcard(postcard::Error),
}

impl From<postcard::Error> for StampError {
    fn from(value: postcard::Error) -> Self {
        StampError::Postcard(value)
    }
}

pub fn stamp(
    ctr: &mut u64,
    key: &[u8; 64],
    package: StampRequiredPackage,
) -> Result<StampedPackage, StampError> {
    let payload = postcard::to_allocvec(&package)?;
    let mut hmac = <StampHmac as KeyInit>::new_from_slice(key).unwrap();
    hmac.update(&ctr.to_be_bytes());
    hmac.update(&payload);
    let hmac = hmac.finalize_fixed();

    let result = StampedPackage {
        ctr: *ctr,
        hmac: hmac.into(),
        stamped_payload: payload,
    };

    *ctr += 1;

    Ok(result)
}

pub fn check_stamp(
    ctr: &mut u64,
    key: &[u8; 64],
    package: &StampedPackage,
) -> Result<(), StampError> {
    if package.ctr < *ctr {
        return Err(StampError::InvalidCtr);
    }

    let mut hmac = <StampHmac as KeyInit>::new_from_slice(key).unwrap();
    hmac.update(&package.ctr.to_be_bytes());
    hmac.update(&package.stamped_payload);
    if hmac.verify(&package.hmac.into()).is_err() {
        return Err(StampError::InvalidStamp);
    }

    *ctr = package.ctr + 1; // redemption

    Ok(())
}
