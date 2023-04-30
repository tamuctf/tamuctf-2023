use courier_proto::messages::ResponsePackage::FlagResponse;
use courier_proto::messages::StampRequiredPackage;
use courier_proto::{
    messages::CourieredPackage::{self, Response, Stamped, Unstamped},
    messages::ResponsePackage::HailstoneResponse,
    messages::UnstampedPackage::HailstoneRequest,
    read_msg,
};
use std::io::{BufReader, BufWriter, Write};
use std::net::TcpStream;

fn main() {
    let courier_write = TcpStream::connect("127.0.0.1:42069").unwrap();
    let courier_read = courier_write.try_clone().unwrap();

    let mut courier_write = BufWriter::new(courier_write);
    let mut courier_read = BufReader::new(courier_read);

    let mut max = 0;
    for i in 0..4096 {
        courier_proto::into_msg(Unstamped(HailstoneRequest(i)))
            .try_for_each(|b| courier_write.write(&[b]).map(|_| ()))
            .unwrap();
        courier_write.flush().unwrap();

        let resp: CourieredPackage = read_msg::<_, _, { u16::MAX }>(&mut courier_read).unwrap();
        let Response(HailstoneResponse(hail)) = resp else { unreachable!() };
        if hail > max {
            max = hail;
        }
        println!("(max: {max}): {i} => {hail}");
    }

    let stamped = courier_proto::stamps::stamp(
        &mut 0,
        include_bytes!("../../stamp.key"),
        StampRequiredPackage::FlagRequest,
    )
    .unwrap();
    courier_proto::into_msg(Stamped(stamped))
        .try_for_each(|b| courier_write.write(&[b]).map(|_| ()))
        .unwrap();
    courier_write.flush().unwrap();
    let resp: CourieredPackage = read_msg::<_, _, { u16::MAX }>(&mut courier_read).unwrap();
    let Response(FlagResponse(flag)) = resp else { unreachable!() };
    println!("{}", flag);
}
