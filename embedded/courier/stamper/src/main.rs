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

const STAMP_KEY: &[u8; 64] = include_bytes!("../../stamp.key");

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[rtic::app(device = lm3s6965, dispatchers = [GPIOA, GPIOB])]
mod app {
    use crate::{HEAP, HEAP_SIZE, STAMP_KEY};
    use alloc::vec::Vec;
    #[cfg(feature = "debug")]
    use cortex_m_semihosting::heprintln;
    use courier_proto::messages::StampRequiredPackage;
    use courier_proto::stamps::stamp;
    use courier_proto::{into_msg, try_read_msg, ReadMsgError};
    use lm3s6965_uart::{
        ManageUART, ReadUART, UARTAddress, UARTPeripheral, UARTPeripheralManageHalf,
        UARTPeripheralReadHalf, UARTPeripheralWriteHalf, WriteUART,
    };

    #[shared]
    struct Shared {}

    #[local]
    struct Local {
        sender_manage: UARTPeripheralManageHalf,
        sender_rx: UARTPeripheralReadHalf,
        sender_tx: UARTPeripheralWriteHalf,
        stamp_ctr: usize,
        next_msg: Option<StampRequiredPackage>,
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

        let (sender_manage, sender_rx, sender_tx) =
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
                sender_manage,
                sender_rx,
                sender_tx,
                stamp_ctr: 0,
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

    #[task(binds = UART0, priority = 1, local = [sender_rx, next_msg, rx_buf])]
    fn recv_msg(cx: recv_msg::Context) {
        let next_msg = cx.local.next_msg;
        if let Some(msg) = next_msg.take() {
            if let Err(failed_msg) = send_msg::spawn(msg) {
                *next_msg = Some(failed_msg);
                return;
            }
        }

        let uart = cx.local.sender_rx;
        let rx_buf = cx.local.rx_buf;

        while uart.rx_avail() {
            let b = uart.readb().unwrap();
            rx_buf.push(b);
            match try_read_msg::<_, { 1 << 12 }, true>(rx_buf) {
                Err(ReadMsgError::NotYetDone) => {}
                Ok(msg) => {
                    if let Err(msg) = send_msg::spawn(msg) {
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

    #[task(priority = 2, capacity = 1, local = [sender_manage, sender_tx, stamp_ctr])]
    fn send_msg(cx: send_msg::Context, msg: StampRequiredPackage) {
        let stamp_ctr = cx.local.stamp_ctr;
        let stamped = stamp(stamp_ctr, STAMP_KEY, msg).expect("Couldn't stamp message");

        let sender_manage = cx.local.sender_manage;
        let sender_tx = cx.local.sender_tx;

        sender_manage
            .update_interrupts()
            .update_transmit_interrupt(true)
            .commit();

        for b in into_msg(stamped) {
            while !sender_tx.tx_avail() {
                cortex_m::asm::wfi();
            }
            sender_tx.writeb(b);
        }

        sender_manage
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
