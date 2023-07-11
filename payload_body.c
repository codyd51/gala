//
//  payload_body.c
//  jailbreak
//
//  Created by Phillip Tennen on 08/07/2023.
//

#include <stdint.h>
#include <stddef.h>

/*.set    RET_ADDR,            0x7ef
 .set    loadaddr,            0x84000000
 .set    maxsize,            0x24000
 .set    dumpaddr,            0x0
 .set    dumpto,                0x84000000
 .set    dumpsize,            0x10000
*/

#define SENTINEL_ADDRESS 0x84000000

#define DUMP_TO 0x84000000
#define DUMP_FROM SENTINEL_ADDRESS
#define DUMP_SIZE 0x1000

void memcpy(char* dest, char* source, int size) {
    for (int i = 0; i < size; i++) {
        *dest = *source;
        dest += 1;
        source += 1;
    }
}

// PT: Be very careful to not declare/use any global data, as those binary sections are stripped
/*
LDR R3, =usb_wait_for_image
    LDR R0, =LOAD_ADDRESS
    LDR R1, =MAX_SIZE
    BLX R3                                      @ R0 = usb_wait_for_image(LOAD_ADDRESS, MAX_SIZE)
*/
/*
#define usb_wait_for_image_addr 0x84004c84
*/
#define get_dfu_image_addr 0x4c85 // + 1 to go to THUMB
#define image_create_from_memory_addr 0x7469 // + 1 to go to THUMB
#define load_selected_image_addr 0x5f1 // + 1 to go to THUMB
#define nor_power_on_addr 0x4e8d // + 1 to go to THUMB
#define nor_init_addr 0x690d // + 1 to go to THUMB
#define jump_to_addr 0x3971 // + 1 to go to THUMB

#define patch_cmp_instruction_addr 0x840046d2

void c_entry_point(char* pwned_serial, int pwned_serial_len, int pc, int sp) {
    /*
    // Try to draw to the framebuffer
    unsigned int *p = 0;
    for(p = (unsigned int*)0x5F700000; p < (unsigned int*)(0x5F700000 + (640 * 960 * 4)); p++) {
        *p = 0xff0088;
    }
     */
    //return;
    
    // Overwrite the serial number
    // PT: Overwriting the serial number causes the device to not come back up after uploading IBSS/IBEC?
    /*
    char* serial = (char*)0x8402e0e0;
    memcpy(serial, pwned_serial, pwned_serial_len);
     */
    
    /*
    uint32_t* sentinel_buffer = (uint32_t*)SENTINEL_ADDRESS;
    sentinel_buffer[0] = 0xdeadbeef;
    // PC is near 0x8402b044 (within the load region)
    // Relocated PC is near 0x84039830 (within the stack region?!)
    // SP is near 0x8403bfa0 (near the top of the main stack)
    //            0x8403bfa0
    sentinel_buffer[1] = pc;
    sentinel_buffer[2] = sp;
     */
    
    //return;
    
    // For some reason doing a while (1) {}
    // while trying to reset the device host-side causes the device to crash...
    // Maybe something about the USB interrupts getting into a bad state?
    
    int (*get_dfu_image)(int load_address, int max_size) = (void*)get_dfu_image_addr;
    int (*image_create_from_memory)(int addr, int size, int arg3) = (void*)image_create_from_memory_addr;
    int (*load_selected_image)(int image_addr, int type_tag, int load_addr, int loaded_length, int boot_flags) = (void*)load_selected_image_addr;
    int (*nor_power_on)(int arg1, int arg2, int arg3) = (void*)nor_power_on_addr;
    int (*nor_init)(int arg1) = (void*)nor_init_addr;
    int (*jump_to)(int arg1, int arg2, int arg3) = (void*)jump_to_addr;
    
    // Crash if nor_power_on + nor_init
    // nor_power_on alone works
    //nor_power_on(1, 1, 0);
    // nor_init causes the crash
    //nor_init(0);
    
    /*
    char* serial = (char*)0x8402e0e0;
    memcpy(serial, pwned_serial, pwned_serial_len);
     */
    
    // not really good to spinloop here because it prevents us from talking over USB?
    /*
    return;
    
    while (1) {}
    */
    
    uint8_t* ibss_tag_addr = 0x854;
    // 0x84000000
    
    //int (*jump_to)() = (void*)memz_create_addr;
    int load_address = 0x84000000;
    
    // Returns 0x00011000
    int get_dfu_image_result = get_dfu_image(load_address, 0x2c000);
    
    size_t loaded_length = (size_t)get_dfu_image_result;
    // Returns 0x84030a88
    int loaded_image = image_create_from_memory(load_address, loaded_length, 0);
    
#define IMAGE_TYPE_IBSS            'ibss'    // iboot single stage
    uint32_t type = IMAGE_TYPE_IBSS;
    
    int load_retval = load_selected_image(
        loaded_image,
        // 0x850 contains ILLB, 0x854 contains IBSS (no null terminator in between them)
        //0x854,
        // Try doing it the same way it's done in the source
        type,
        // Hard-coded in the boot ROM
        load_address,
        loaded_length,
        0
    );
    
    /*
    uint32_t* sentinel_buffer = (uint32_t*)SENTINEL_ADDRESS;
    sentinel_buffer[0] = 0xcafebabe;
    sentinel_buffer[1] = get_dfu_image_result;
     */
    /*
    sentinel_buffer[2] = loaded_length;
    sentinel_buffer[3] = loaded_image;
    sentinel_buffer[4] = load_retval;
     */

    /*
    char* mem = (char*)patch_cmp_instruction_addr;
    mem[0] = 0x80;
    mem[1] = 0x42;
    */
    //jump_to(0, load_address, 0);

    //memcpy(DUMP_TO, DUMP_FROM, DUMP_SIZE);
    
    void (*entry_point)(int arg1, int arg2, int arg3, int arg4) = (void*)load_address;
    entry_point(0, 0, 0, 0);
}

/*
 entry_point:
     LDR    R0,    =dumpto
     LDR    R1,    =dumpaddr
     LDR    R2,    =dumpsize
     BL    memcpy

     LDR    R0,    =loadaddr
     LDR    R1,    =maxsize
     MOV    R2,    #0
     LDR    R3,    =RET_ADDR
     BLX    R3
 @-----------------------------------------------------
 memcpy:

 _memcpy_loop:
         LDRB     R3,     [R1]
         STRB     R3,     [R0]
         ADD     R0,     #1
         ADD     R1,     #1
         SUB     R2,     #1
         CMP     R2,     #0
         BNE     _memcpy_loop

         BX      LR

 */
