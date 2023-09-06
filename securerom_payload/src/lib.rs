#![no_std]
#![feature(lang_items)]
use core;
use core::panic::PanicInfo;

// PT: Make sure that the Rust entry point is the first defined function, as it's helpful
// for it to sit right at the start of __text.

const USB_RECV_REGION_BASE: usize = 0x84000000;
const USB_RECV_REGION_SIZE: usize = 0x2c000;

// Note that each function pointer here has + 1 added so that branches to these addresses switch to THUMB if necessary
const FUNC_ADDR_NOR_POWER_ON: usize = 0x4e8d;
const FUNC_ADDR_NOR_INIT: usize = 0x690d;
const FUNC_ADDR_FREE: usize = 0x3b95;
const FUNC_ADDR_GET_DFU_IMAGE: usize = 0x4c85;

#[no_mangle] pub unsafe extern "C"
//fn await_image() -> i32 {
fn c_entry_point() -> i32 {
    //call_func3_at_addr(FUNC_ADDR_NOR_POWER_ON, 1, 1, 0);
    //call_func1_at_addr(FUNC_ADDR_NOR_INIT, 0);
    0
}

#[no_mangle] pub unsafe extern "C"
fn get_image() -> usize {
    let image_info = call_func2_at_addr(FUNC_ADDR_GET_DFU_IMAGE, USB_RECV_REGION_BASE, USB_RECV_REGION_SIZE);

    let leaking_dfu_buffer_ptr = 0x8402dbcc as *mut usize;
    let leaking_dfu_buffer_val = *leaking_dfu_buffer_ptr;
    *leaking_dfu_buffer_ptr = 0;
    call_func1_at_addr(FUNC_ADDR_FREE, leaking_dfu_buffer_val);

    return image_info;
}

// Everything that follows is extremely unsafe
//
// PT: There's a way to DRY this with macros, but I had trouble getting a proc-macro to build
// with the armv7-apple-ios toolchain

unsafe fn func0_from_addr(addr: usize) -> extern "C" fn() -> usize {
    core::mem::transmute(addr as *const ())
}

unsafe fn call_func0_at_addr(addr: usize) -> usize {
    let f = func0_from_addr(addr);
    f()
}

unsafe fn func1_from_addr(addr: usize) -> extern "C" fn(usize) -> usize {
    core::mem::transmute(addr as *const ())
}

unsafe fn call_func1_at_addr(addr: usize, arg0: usize) -> usize {
    let f = func1_from_addr(addr);
    f(arg0)
}

unsafe fn func2_from_addr(addr: usize) -> extern "C" fn(usize, usize) -> usize {
    core::mem::transmute(addr as *const ())
}

unsafe fn call_func2_at_addr(addr: usize, arg0: usize, arg1: usize) -> usize {
    let f = func2_from_addr(addr);
    f(arg0, arg1)
}

unsafe fn func3_from_addr(addr: usize) -> extern "C" fn(usize, usize, usize) -> usize {
    core::mem::transmute(addr as *const ())
}

unsafe fn call_func3_at_addr(addr: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let f = func3_from_addr(addr);
    f(arg0, arg1, arg2)
}

#[lang = "eh_personality"] extern fn eh_personality() {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
