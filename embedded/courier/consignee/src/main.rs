#![deny(unsafe_code)]
#![deny(warnings)]
#![allow(unused_variables)] // for featuring
#![no_main]
#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

#[cfg(feature = "debug")]
use cortex_m_semihosting::{
    debug::{exit, EXIT_FAILURE},
    heprintln,
};
#[cfg(feature = "debug")]
use panic_semihosting as _;

use core::alloc::Layout;
use embedded_alloc::Heap;

const HEAP_SIZE: usize = 1 << 14;

#[global_allocator]
static HEAP: Heap = Heap::empty();

pub fn hailstone(value: u16) -> u16 {
    let mut steps = 0;
    let mut current = value as u32;
    while current > 1 {
        if current % 2 == 0 {
            current = current / 2;
        } else {
            current = 3 * current + 1;
        }
        steps += 1;
    }
    steps
}

#[rtic::app(device = lm3s6965, dispatchers = [GPIOA, GPIOB])]
mod app {
    use crate::{hailstone, HEAP, HEAP_SIZE};
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    #[cfg(feature = "debug")]
    use cortex_m_semihosting::heprintln;
    use courier_proto::messages::{
        CourieredPackage, ResponsePackage, StampRequiredPackage, UnstampedPackage,
    };
    use courier_proto::{into_msg, try_read_msg, ReadMsgError};
    use lm3s6965_uart::{
        ManageUART, ReadUART, UARTAddress, UARTPeripheral, UARTPeripheralManageHalf,
        UARTPeripheralReadHalf, UARTPeripheralWriteHalf, WriteUART,
    };

    #[shared]
    struct Shared {}

    #[local]
    struct Local {
        courier_manage: UARTPeripheralManageHalf,
        courier_rx: UARTPeripheralReadHalf,
        courier_tx: UARTPeripheralWriteHalf,
        next_msg: Option<CourieredPackage>,
        rx_buf: Vec<u8>,
    }

    #[init]
    #[allow(unsafe_code)]
    fn init(_: init::Context) -> (Shared, Local, init::Monotonics) {
        {
            use core::mem::MaybeUninit;
            static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
        }

        let (courier_manage, courier_rx, courier_tx) =
            unsafe { UARTPeripheral::new(UARTAddress::UART0) }
                .enable_transmit(true)
                .enable_receive(true)
                .enable_fifo(true)
                .enable_break_interrupt(true)
                .enable_receive_interrupt(true)
                .finish()
                .split();

        (
            Shared {},
            Local {
                courier_manage,
                courier_rx,
                courier_tx,
                next_msg: None,
                rx_buf: Vec::new(),
            },
            init::Monotonics(),
        )
    }

    #[idle]
    fn idle(_: idle::Context) -> ! {
        loop {
            cortex_m::asm::wfi(); // peacefully sleep *honk mimimimi*
        }
    }

    #[task(binds = UART0, priority = 1, local = [courier_rx, next_msg, rx_buf])]
    fn recv_msg(cx: recv_msg::Context) {
        let next_msg = cx.local.next_msg;
        if let Some(msg) = next_msg.take() {
            if let Err(failed_msg) = respond_to_msg::spawn(msg) {
                *next_msg = Some(failed_msg);
                return;
            }
        }

        let uart = cx.local.courier_rx;
        let rx_buf = cx.local.rx_buf;

        while uart.rx_avail() {
            let Ok(b) = uart.readb() else { return; };
            rx_buf.push(b);
            // reduced size since we have to deserialise the signed packages
            match try_read_msg::<_, { 1 << 10 }, true>(rx_buf) {
                Err(ReadMsgError::NotYetDone) => {}
                Ok(msg) => {
                    if let Err(msg) = respond_to_msg::spawn(msg) {
                        *next_msg = Some(msg);
                        return;
                    }
                }
                Err(e) => {
                    #[cfg(feature = "debug")]
                    heprintln!("error while processing: {:?}", e);
                }
            }
        }
    }

    #[task(priority = 2, capacity = 4, local = [courier_manage, courier_tx])]
    fn respond_to_msg(cx: respond_to_msg::Context, msg: CourieredPackage) {
        let resp = match msg {
            CourieredPackage::Unstamped(unstamped) => match unstamped {
                UnstampedPackage::HailstoneRequest(base) => {
                    ResponsePackage::HailstoneResponse(hailstone(base))
                }
            },
            CourieredPackage::Stamped(stamped) => {
                let stamped = match stamped.unpack() {
                    Ok(pkg) => pkg,
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        heprintln!("couldn't deserialised a signed package: {:?}", e);
                        return;
                    }
                };
                match stamped {
                    StampRequiredPackage::WeddingInvitation { .. } => {
                        ResponsePackage::WeddingResponse(
                            "Oh! How kind! I don't think I can make it... :(".to_string(),
                        )
                    }
                    StampRequiredPackage::FlagRequest => ResponsePackage::FlagResponse(format!(
                        "Oh, sure! Here you go: {}",
                        include_str!("../../flag.txt")
                    )),
                }
            }
            CourieredPackage::Response(_) => {
                #[cfg(feature = "debug")]
                heprintln!("bad delivery request detected: {:?}", msg);
                return;
            }
        };

        let courier_manage = cx.local.courier_manage;
        let courier_tx = cx.local.courier_tx;

        courier_manage
            .update_interrupts()
            .update_transmit_interrupt(true)
            .commit();

        for b in into_msg(CourieredPackage::Response(resp)) {
            while !courier_tx.tx_avail() {
                cortex_m::asm::wfi();
            }
            courier_tx.writeb(b);
        }

        courier_manage
            .update_interrupts()
            .update_transmit_interrupt(false)
            .commit();
    }
}

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    #[cfg(feature = "debug")]
    heprintln!("Whoops! Ran out of memory while executing.");
    #[cfg(feature = "debug")]
    exit(EXIT_FAILURE);

    loop {
        cortex_m::asm::nop();
    }
}

#[cfg(not(feature = "debug"))]
#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    loop {
        cortex_m::asm::nop()
    }
}
