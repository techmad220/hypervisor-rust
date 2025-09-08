//! Main entry point for hypervisor

#![no_std]
#![no_main]

use hypervisor::Hypervisor;
use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Initialize hypervisor
    match Hypervisor::init() {
        Ok(_) => {},
        Err(_) => halt(),
    }
    
    // Main hypervisor loop
    hypervisor::hypervisor_main()
}

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt()
}