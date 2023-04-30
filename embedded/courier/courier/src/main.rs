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

#[rtic::app(device = lm3s6965, dispatchers = [GPIOA, GPIOB, GPIOC])]
mod app {
    use crate::{HEAP, HEAP_SIZE, STAMP_KEY};
    use alloc::vec::Vec;
    use core::mem::swap;
    #[cfg(feature = "debug")]
    use cortex_m_semihosting::heprintln;
    use courier_proto::messages::CourieredPackage;
    use courier_proto::stamps::check_stamp;
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
        consignee_manage: UARTPeripheralManageHalf,
        consignee_rx: UARTPeripheralReadHalf,
        consignee_tx: UARTPeripheralWriteHalf,
        stamp_ctr: u64,
        next_msg_sender: Option<CourieredPackage>,
        next_msg_consignee: Option<(Vec<u8>, CourieredPackage)>,
        rx_buf_sender: Vec<u8>,
        rx_buf_consignee: Vec<u8>,
    }

    #[init]
    #[allow(unsafe_code)]
    #[allow(unreachable_code)]
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

        let (consignee_manage, consignee_rx, consignee_tx) =
            unsafe { UARTPeripheral::new(UARTAddress::UART1) }
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
                consignee_manage,
                consignee_rx,
                consignee_tx,
                stamp_ctr: 0,
                next_msg_sender: None,
                next_msg_consignee: None,
                rx_buf_sender: Vec::new(),
                rx_buf_consignee: Vec::new(),
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

    #[task(binds = UART0, priority = 1, local = [sender_rx, next_msg_consignee, rx_buf_sender])]
    fn recv_msg_sender(cx: recv_msg_sender::Context) {
        let next_msg = cx.local.next_msg_consignee;
        if let Some(msg) = next_msg.take() {
            if let Err(failed_msg) = send_msg_consignee::spawn(msg) {
                *next_msg = Some(failed_msg);
                return;
            }
        }

        let uart = cx.local.sender_rx;
        let rx_buf = cx.local.rx_buf_sender;

        while uart.rx_avail() {
            let Ok(b) = uart.readb() else { return; };
            rx_buf.push(b);
            match try_read_msg::<_, { 1 << 12 }, false>(rx_buf) {
                Err(ReadMsgError::NotYetDone) => {}
                Ok(msg) => {
                    let mut prev_buf = Vec::new();
                    swap(rx_buf, &mut prev_buf);
                    if let Err(msg) = send_msg_consignee::spawn((prev_buf, msg)) {
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

    #[task(priority = 3, capacity = 1, local = [consignee_manage, consignee_tx, stamp_ctr])]
    fn send_msg_consignee(
        cx: send_msg_consignee::Context,
        (prev_buf, msg): (Vec<u8>, CourieredPackage),
    ) {
        match &msg {
            CourieredPackage::Unstamped(_) => {}
            CourieredPackage::Stamped(stamped) => {
                let stamp_ctr = cx.local.stamp_ctr;
                match check_stamp(stamp_ctr, STAMP_KEY, stamped) {
                    Ok(_) => {}
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        heprintln!("stamp check failed: {:?}", e);
                        return; // we received an invalid stamp/message
                    }
                }
            }
            msg => {
                #[cfg(feature = "debug")]
                heprintln!("bad delivery request detected: {:?}", msg);
                return;
            }
        };
        drop(msg);

        let consignee_manage = cx.local.consignee_manage;
        let consignee_tx = cx.local.consignee_tx;

        consignee_manage
            .update_interrupts()
            .update_transmit_interrupt(true)
            .commit();

        for b in prev_buf {
            while !consignee_tx.tx_avail() {
                cortex_m::asm::wfi();
            }
            consignee_tx.writeb(b);
        }

        consignee_manage
            .update_interrupts()
            .update_transmit_interrupt(false)
            .commit();
    }

    #[task(binds = UART1, priority = 2, local = [consignee_rx, next_msg_sender, rx_buf_consignee])]
    fn recv_msg_consignee(cx: recv_msg_consignee::Context) {
        let next_msg = cx.local.next_msg_sender;
        if let Some(msg) = next_msg.take() {
            if let Err(failed_msg) = send_msg_sender::spawn(msg) {
                *next_msg = Some(failed_msg);
                return;
            }
        }

        let uart = cx.local.consignee_rx;
        let rx_buf = cx.local.rx_buf_consignee;

        while uart.rx_avail() {
            let Ok(b) = uart.readb() else { return; };
            rx_buf.push(b);
            match try_read_msg::<_, { 1 << 12 }, true>(rx_buf) {
                Err(ReadMsgError::NotYetDone) => {}
                Ok(msg) => {
                    if let Err(msg) = send_msg_sender::spawn(msg) {
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

    #[task(priority = 4, capacity = 1, local = [sender_manage, sender_tx])]
    fn send_msg_sender(cx: send_msg_sender::Context, msg: CourieredPackage) {
        if !matches!(msg, CourieredPackage::Response(_)) {
            #[cfg(feature = "debug")]
            heprintln!("bad delivery response detected: {:?}", msg);
            return;
        }

        let sender_manage = cx.local.sender_manage;
        let sender_tx = cx.local.sender_tx;

        sender_manage
            .update_interrupts()
            .update_transmit_interrupt(true)
            .commit();

        for b in into_msg(msg) {
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
