#![no_std]
#![feature(lang_items)]
use core;
use core::panic::PanicInfo;

const USB_RECV_REGION_BASE: usize = 0x84000000;
const USB_RECV_REGION_SIZE: usize = 0x2c000;

// Note that each function pointer here has + 1 added so that branches to these addresses switch to THUMB if necessary
const FUNC_ADDR_GET_DFU_IMAGE: usize = 0x4c85;
const FUNC_ADDR_MEMZ_CREATE: usize = 0x7469;
const FUNC_ADDR_JUMP_TO_LOADED_IMAGE: usize = 0x5a5d;

extern "C" {
    // Defined in assembly
    fn image3_load_no_signature_check(memz_image: usize, arg2: *mut usize, arg3: *mut usize) -> usize;
}

#[no_mangle] pub unsafe extern "C"
fn receive_image_over_usb() -> usize {
    let image_info = call_func2_at_addr(FUNC_ADDR_GET_DFU_IMAGE, USB_RECV_REGION_BASE, USB_RECV_REGION_SIZE);
    image_info
}

#[no_mangle] pub unsafe extern "C"
fn receive_and_jump_to_image() -> ! {
    let image_base_addr = receive_image_over_usb();
    let memz_image = call_func3_at_addr(FUNC_ADDR_MEMZ_CREATE, USB_RECV_REGION_BASE, image_base_addr, 0);

    let mut load_address = USB_RECV_REGION_BASE;
    let mut new_image_base_addr = image_base_addr;
    image3_load_no_signature_check(memz_image, &mut load_address as *mut _, &mut new_image_base_addr as *mut _);

    // This will never return, and the image will take over control of the system
    call_func3_at_addr(FUNC_ADDR_JUMP_TO_LOADED_IMAGE, 0, load_address, 0)
}

// Everything that follows is extremely unsafe
//
// PT: There's a way to DRY this with macros, but I had trouble getting a proc-macro to build
// with the armv7-apple-ios toolchain
//
// PT: Defining a function generic over its arity would be useful here
unsafe fn func2_from_addr<T>(addr: usize) -> extern "C" fn(usize, usize) -> T {
    core::mem::transmute(addr as *const ())
}

unsafe fn call_func2_at_addr<T>(addr: usize, arg0: usize, arg1: usize) -> T {
    let f = func2_from_addr(addr);
    f(arg0, arg1)
}

unsafe fn func3_from_addr<T>(addr: usize) -> extern "C" fn(usize, usize, usize) -> T {
    core::mem::transmute(addr as *const ())
}

unsafe fn call_func3_at_addr<T>(addr: usize, arg0: usize, arg1: usize, arg2: usize) -> T {
    let f = func3_from_addr(addr);
    f(arg0, arg1, arg2)
}

#[lang = "eh_personality"] extern fn eh_personality() {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
