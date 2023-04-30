use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum UnstampedPackage {
    HailstoneRequest(u16),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum StampRequiredPackage {
    WeddingInvitation {
        when: u64,
        marrying_parties: Vec<String>,
        details: Vec<u8>,
    },
    FlagRequest,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ResponsePackage {
    HailstoneResponse(u16),
    WeddingResponse(String),
    FlagResponse(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CourieredPackage {
    Unstamped(UnstampedPackage),
    Stamped(StampedPackage),
    Response(ResponsePackage),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StampedPackage {
    pub ctr: u64,
    pub hmac: [u8; 32],
    pub stamped_payload: Vec<u8>,
}

impl StampedPackage {
    pub fn unpack(self) -> Result<StampRequiredPackage, postcard::Error> {
        postcard::from_bytes(&self.stamped_payload)
    }
}
