#![no_std]
//#![feature(start)]
#![feature(lang_items)]
use core;
use core::panic::PanicInfo;

#[lang = "eh_personality"] extern fn eh_personality() {}


fn write_str(
    a: &[u32],
    b: &mut usize,
    c: &str,
    ) {
    //println!("b {b:?} c {c:?}");
}

fn write_u32(
    a: &[u32],
    b: &mut usize,
    c: u32,
    ) {
    //println!("b {b:?} c {c:?}");
}

//#[start]
//#[allow(unreachable_code)]
fn start(_argc: isize, _argv: *const *const u8) -> isize {
//fn main() -> () {
    let pc = 0_u32;
    let sp = 1_u32;
    let ret = 2_u32;
    let communication_area = unsafe { core::slice::from_raw_parts_mut(0x84000000 as *mut _, 1024) };
    communication_area[0] = pc;
    communication_area[1] = sp;
    let mut cursor = 0;
    write_str(
        communication_area,
        &mut cursor,
        "Output from image3_decrypt_payload: ",
    );
    write_u32(
        communication_area,
        &mut cursor,
        ret
        );

    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
