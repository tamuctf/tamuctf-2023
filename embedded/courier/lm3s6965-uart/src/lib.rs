// this file modified from: https://github.com/TAMU-CSE/mitre-ectf2021/blob/master/controller/scewl-rust/src/interface.rs
#![allow(unsafe_code)]
#![allow(clippy::upper_case_acronyms)]
#![allow(warnings)]
#![no_std]

use core::fmt::{Debug, Formatter, Pointer};

use volatile_register::{RO, RW, WO};

mod consts;
use consts::*;

/// The UART struct as specified by the CMSIS specification (and, more specifically, [line 620 of `lm3s_cmsis.h`](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/lm3s/lm3s_cmsis.h#L620))
///
/// This implementation differs slightly in that [volatile registers](https://docs.rs/volatile-register/0.2.0/volatile_register/)
/// are used in place of type metadata [as defined in `core_cm3.h`](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/CMSIS/Include/core_cm3.h#L197)
/// to compile-time enforce appropriate reading and writing to these registers.
///
/// Otherwise, this struct should never be instantiated, but instead static mutable references to
/// raw pointers (which point to the [various memory-mapped UART peripherals](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/lm3s/lm3s_cmsis.h#L876))
/// should be derived via [raw pointer to reference casting](https://docs.rust-embedded.org/book/c-tips/index.html#references-vs-pointers).
#[repr(C)]
pub struct RawUART {
    /// Data register
    dr: RW<u32>,
    /// Receive status register
    rsr: RW<u32>,
    /// A reserved region with no explicit use
    reserved1: [u8; 16],
    /// Flag register
    fr: RO<u32>,
    /// A reserved region with no explicit use
    reserved2: [u8; 4],
    /// UART IrDA low-power register
    ilpr: RW<u32>,
    /// Integer baud rate divisor register
    ibrd: RW<u32>,
    /// Fractional baud rate divisor register
    fbrd: RW<u32>,
    /// UART line control
    lcrh: RW<u32>,
    /// Control register
    ctl: RW<u32>,
    /// Interrupt FIFO level select register
    ifls: RW<u32>,
    /// Interrupt mask set/clear register
    im: RW<u32>,
    /// Raw interrupt status register
    ris: RO<u32>,
    /// Masked interrupt status register
    mis: RO<u32>,
    /// Interrupt clear register
    icr: WO<u32>,
    /// UART DMA control
    dmactl: RW<u32>,
}

/// Memory-mapped UART peripheral addresses for the different serial lines, which will then be
/// copied to the sockets for the respective data lines being emulated
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum UARTAddress {
    /// Address of UART0
    UART0 = 0x4000_C000,
    /// Address of UART1
    UART1 = 0x4000_D000,
    /// Address of UART2
    UART2 = 0x4000_E000,
}

pub trait AsRawUART {
    fn uart<'a>(&mut self) -> &'a mut RawUART;
}

pub struct ReadError<const ERR_ONLY: bool> {
    read: u32,
}

impl ReadError<true> {
    pub fn overrun(&self) -> bool {
        self.read & UARTRSR_OE != 0
    }

    pub fn broken(&self) -> bool {
        self.read & UARTRSR_BE != 0
    }

    pub fn parity(&self) -> bool {
        self.read & UARTRSR_PE != 0
    }

    pub fn framing(&self) -> bool {
        self.read & UARTRSR_FE != 0
    }

    pub fn any(&self) -> bool {
        self.read & UARTRSR_ERR != 0
    }
}

impl Debug for ReadError<true> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReadError")
            .field("is_overrun", &self.overrun())
            .field("is_broken", &self.broken())
            .field("parity_failed", &self.parity())
            .field("framing_failed", &self.framing())
            .finish()
    }
}

impl ReadError<false> {
    pub fn overrun(&self) -> bool {
        self.read & UARTDR_OE != 0
    }

    pub fn broken(&self) -> bool {
        self.read & UARTDR_BE != 0
    }

    pub fn parity(&self) -> bool {
        self.read & UARTDR_PE != 0
    }

    pub fn framing(&self) -> bool {
        self.read & UARTDR_FE != 0
    }

    pub fn any(&self) -> bool {
        self.read & UARTRSR_ERR != 0
    }

    pub fn data(&self) -> u8 {
        self.read as u8
    }
}

impl Debug for ReadError<false> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReadError")
            .field("is_overrun", &self.overrun())
            .field("is_broken", &self.broken())
            .field("parity_failed", &self.parity())
            .field("framing_failed", &self.framing())
            .field("data", &self.data())
            .finish()
    }
}

macro_rules! define_modifier {
    ($fn_name:ident, $field:ident, $bits:ident) => {
        pub fn $fn_name(mut self, enable: bool) -> Self {
            if enable {
                self.$field |= $bits;
            } else {
                self.$field &= !$bits;
            }
            self
        }
    };
}

pub struct UpdateUARTIM<'a, M: ManageUART> {
    manager: &'a mut M,
    im: u32,
}

impl<'a, M: ManageUART> UpdateUARTIM<'a, M> {
    define_modifier!(update_overflow_interrupt, im, UARTIM_OEIM);
    define_modifier!(update_break_interrupt, im, UARTIM_BEIM);
    define_modifier!(update_parity_interrupt, im, UARTIM_PEIM);
    define_modifier!(update_framing_interrupt, im, UARTIM_FEIM);
    define_modifier!(update_receive_timeout_interrupt, im, UARTIM_RTIM);
    define_modifier!(update_transmit_interrupt, im, UARTIM_TXIM);
    define_modifier!(update_receive_interrupt, im, UARTIM_RXIM);

    pub fn commit(self) {
        unsafe {
            self.manager.uart().im.write(self.im);
        }
        self.manager.reset();
    }
}

pub trait ManageUART: AsRawUART + Sized {
    fn update_interrupts(&mut self) -> UpdateUARTIM<Self> {
        UpdateUARTIM {
            im: self.uart().im.read(),
            manager: self,
        }
    }

    fn reset(&mut self) {
        unsafe {
            let prev = self.uart().ctl.read();
            self.uart().ctl.write(prev & 0xffff_fffe);
            self.uart().ctl.write(prev | 0x1);
        }
    }
}

pub trait ReadUART: AsRawUART {
    fn rx_avail(&mut self) -> bool {
        self.uart().fr.read() & UARTFR_RXFE == 0
    }

    fn rx_error(&mut self) -> ReadError<true> {
        let read = unsafe { self.uart().rsr.read() };
        ReadError { read }
    }

    fn readb(&mut self) -> Result<u8, ReadError<false>> {
        let read = unsafe { self.uart().dr.read() };
        if read & UARTDR_ERR != 0 {
            Err(ReadError { read })
        } else {
            Ok(read as u8)
        }
    }
}

pub trait WriteUART: AsRawUART {
    fn tx_avail(&mut self) -> bool {
        self.uart().fr.read() & UARTFR_TXFF == 0
    }

    fn writeb(&mut self, b: u8) {
        unsafe { self.uart().dr.write(b as u32) };
    }
}

/// Wrapper type for interfacing with the UART peripherals
///
/// This type is effectively equivalent to the struct defined in the original C implementation, but
/// methods are defined on the interface instead to restrict operations to a theoretically safe
/// subset of operations on the UART peripheral.
pub struct UARTPeripheral {
    /// The UART adapter to be manipulated by this wrapper
    uart: *mut RawUART,
}

pub struct UARTPeripheralReadHalf {
    /// The UART adapter to be manipulated by this wrapper
    uart: *mut RawUART,
}

pub struct UARTPeripheralWriteHalf {
    /// The UART adapter to be manipulated by this wrapper
    uart: *mut RawUART,
}

pub struct UARTPeripheralManageHalf {
    /// The UART adapter to be manipulated by this wrapper
    uart: *mut RawUART,
}

impl AsRawUART for UARTPeripheral {
    fn uart<'a>(&mut self) -> &'a mut RawUART {
        unsafe { self.uart.as_mut().unwrap_unchecked() }
    }
}

unsafe impl Send for UARTPeripheral {}

impl ManageUART for UARTPeripheral {}
impl ReadUART for UARTPeripheral {}
impl WriteUART for UARTPeripheral {}

impl AsRawUART for UARTPeripheralReadHalf {
    fn uart<'a>(&mut self) -> &'a mut RawUART {
        unsafe { self.uart.as_mut().unwrap_unchecked() }
    }
}

unsafe impl Send for UARTPeripheralReadHalf {}

impl ReadUART for UARTPeripheralReadHalf {}

impl AsRawUART for UARTPeripheralWriteHalf {
    fn uart<'a>(&mut self) -> &'a mut RawUART {
        unsafe { self.uart.as_mut().unwrap_unchecked() }
    }
}

unsafe impl Send for UARTPeripheralWriteHalf {}

impl WriteUART for UARTPeripheralWriteHalf {}

impl AsRawUART for UARTPeripheralManageHalf {
    fn uart<'a>(&mut self) -> &'a mut RawUART {
        unsafe { self.uart.as_mut().unwrap_unchecked() }
    }
}

unsafe impl Send for UARTPeripheralManageHalf {}

impl ManageUART for UARTPeripheralManageHalf {}

pub struct UARTUpdater<M: ManageUART> {
    inner: M,
    ctl: u32,
    ibrd: u32,
    fbrd: u32,
    lcrh: u32,
    im: u32,
}

macro_rules! define_enabler {
    ($fn_name:ident, $field:ident, $bits:ident) => {
        pub fn $fn_name(mut self, enable: bool) -> Self {
            if enable {
                self.$field |= $bits;
            } else {
                self.$field &= !$bits;
            }
            self
        }
    };
}

impl<M: ManageUART> UARTUpdater<M> {
    fn new(raw: M) -> Self {
        Self {
            inner: raw,
            ctl: 0,
            ibrd: 0xa,
            fbrd: 0x36,
            lcrh: 0x60,
            im: 0x0,
        }
    }

    define_enabler!(enable_receive, ctl, UARTCTL_RXE);
    define_enabler!(enable_transmit, ctl, UARTCTL_TXE);
    define_enabler!(enable_loopback, ctl, UARTCTL_LBE);
    define_enabler!(enable_sir_lowpower, ctl, UARTCTL_SIRLP);
    define_enabler!(enable_sir, ctl, UARTCTL_SIREN);

    define_enabler!(enable_fifo, lcrh, UARTLCRH_FEN);

    define_enabler!(enable_overflow_interrupt, im, UARTIM_OEIM);
    define_enabler!(enable_break_interrupt, im, UARTIM_BEIM);
    define_enabler!(enable_parity_interrupt, im, UARTIM_PEIM);
    define_enabler!(enable_framing_interrupt, im, UARTIM_FEIM);
    define_enabler!(enable_receive_timeout_interrupt, im, UARTIM_RTIM);
    define_enabler!(enable_transmit_interrupt, im, UARTIM_TXIM);
    define_enabler!(enable_receive_interrupt, im, UARTIM_RXIM);

    pub fn finish(mut self) -> M {
        let mut inner = self.inner;
        let uart = inner.uart();

        unsafe {
            uart.ctl.write(uart.ctl.read() & 0xffff_fffe);

            uart.ibrd
                .write((uart.ibrd.read() & !UARTIBRD_MASK) | self.ibrd);
            uart.fbrd
                .write((uart.fbrd.read() & !UARTFBRD_MASK) | self.fbrd);
            uart.lcrh
                .write((uart.lcrh.read() & !UARTLCRH_MASK) | self.lcrh);
            uart.im.write((uart.im.read() & !UARTIM_MASK) | self.im);
            uart.ctl.write(uart.ctl.read() & !UARTCTL_MASK | self.ctl);

            uart.ctl.write(uart.ctl.read() | 0x1);
        }

        inner
    }
}

impl UARTPeripheral {
    pub unsafe fn new(addr: UARTAddress) -> UARTUpdater<Self> {
        UARTUpdater::new(Self {
            uart: &mut *(addr as usize as *mut RawUART),
        })
    }

    pub fn split(
        self,
    ) -> (
        UARTPeripheralManageHalf,
        UARTPeripheralReadHalf,
        UARTPeripheralWriteHalf,
    ) {
        #[allow(clippy::cast_ref_to_mut)]
        (
            UARTPeripheralManageHalf { uart: self.uart },
            UARTPeripheralReadHalf { uart: self.uart },
            UARTPeripheralWriteHalf { uart: self.uart },
        )
    }
}
