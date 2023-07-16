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

struct image_info {
    uint32_t	imageLength;
    uint32_t	imageAllocation;
    uint32_t	imageType;
    uint32_t	imagePrivateMagic;
#define IMAGE_MEMORY_INFO_MAGIC		'Memz'
#define IMAGE2_IMAGE_INFO_MAGIC		'img2'
#define IMAGE3_IMAGE_INFO_MAGIC		'img3'
#define IMAGE4_IMAGE_INFO_MAGIC		'img4'
    uint32_t	imageOptions;
    void		*imagePrivate;
};
#define USB_RECV_REGION_BASE 0x84000000
#define USB_RECV_REGION_SIZE 0x2c000

/*
int image3_load_no_signature_check(int memz_create_output, int* load_address, struct image_info** image_info) {
    int sp_offset = IMAGE3_LOAD_STRUCT_OFFSET;
}
 */

int create_image(int memz);
int continue_loop();

int get_image() {
    //  TODO(PT): Define
    struct image_info* (*get_dfu_image)(int load_address, int max_size) = (void*)get_dfu_image_addr;
    struct image_info* image_info = get_dfu_image(USB_RECV_REGION_BASE, USB_RECV_REGION_SIZE);
    int (*free)(int addr) = (void*)0x3b95;
    // The last part of the image starts or ends at 0x8402ba80, this isn't far off...
    int* gLeakingDFUBufferPtr = (int*)0x8402dbcc;

    //struct image_info* image_info = get_dfu_image(USB_RECV_REGION_BASE, USB_RECV_REGION_SIZE);
    int gLeakingDFUBuffer = *gLeakingDFUBufferPtr;
    *gLeakingDFUBufferPtr = 0;
    free(gLeakingDFUBuffer);
    return image_info;
}

void c_entry_point(void) {
    int (*nor_power_on)(int arg1, int arg2, int arg3) = (void*)nor_power_on_addr;
    int (*nor_init)(int arg1) = (void*)nor_init_addr;
    struct image_info* (*get_dfu_image)(int load_address, int max_size) = (void*)get_dfu_image_addr;
    int (*free)(int addr) = (void*)0x3b95;
    int (*memz_create)(int memory_base, struct image_info* image_info, int arg3) = (void*)0x7469;
    int (*jump_to)(int arg1, int arg2, int arg3) = (void*)0x5a5d;

    nor_power_on(1, 1, 0);
    nor_init(0);

    //continue_loop();
    return;

    while (1) {
        /*
        struct image_info* image_info = get_dfu_image(USB_RECV_REGION_BASE, USB_RECV_REGION_SIZE);
        int gLeakingDFUBuffer = *gLeakingDFUBufferPtr;
        *gLeakingDFUBufferPtr = 0;
        free(gLeakingDFUBuffer);
         */
        /*
        if (image_info < 0) {
            continue;
        }
         */

        //int memz_create_output = memz_create(USB_RECV_REGION_BASE, image_info, 0);
        /*
        if (memz_create_output == 0) {
            continue;
        }
         */

        /*
        int load_address = USB_RECV_REGION_BASE;
        int image_load_retval = image3_load_no_signature_check(memz_create_output, &load_address, &image_info);
        if (image_load_retval != 0) {
            // load failed
            continue;
        }
         */
        //int (*create_image)(int memz
        //int ret = create_image(USB_RECV_REGION_BASE);
        /*
        if (ret != 0) {
            continue;
        }
         */

        //jump_to(0, USB_RECV_REGION_BASE, 0);
    }
}

void c_entry_point_old(char* pwned_serial, int pwned_serial_len, int pc, int sp) {
    /*
    // Try to draw to the framebuffer
    unsigned int *p = 0;
    for(p = (unsigned int*)0x5F700000; p < (unsigned int*)(0x5F700000 + (640 * 960 * 4)); p++) {
        *p = 0xff0088;
    }
     */

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
    nor_power_on(1, 1, 0);
    // nor_init causes the crash
    nor_init(0);
    
    /*
    char* serial = (char*)0x8402e0e0;
    memcpy(serial, pwned_serial, pwned_serial_len);
     */
    
    // not really good to spinloop here because it prevents us from talking over USB?

    uint8_t* ibss_tag_addr = 0x854;
    // 0x84000000

    //int (*jump_to)() = (void*)memz_create_addr;

    // Returns 0x00011000
    // On a failure, returns 0x000109c4
    // I guess this is after we're limiting how many bytes we send to the true size of the file?
    // (This is the correct iBSS size)
    int get_dfu_image_result = get_dfu_image(USB_RECV_REGION_BASE, 0x2c000);
    void (*entry_point)(int arg1, int arg2, int arg3, int arg4) = (void*)USB_RECV_REGION_BASE;
    entry_point(0, 0, 0, 0);

    size_t loaded_length = (size_t)get_dfu_image_result;
    // Returns 0x84030a88
    // Really struct image_info*
    struct image_info* image_info = image_create_from_memory(USB_RECV_REGION_BASE, loaded_length, 0);
    
#define IMAGE_TYPE_IBSS            'ibss'    // iboot single stage
    uint32_t type = IMAGE_TYPE_IBSS;

    /*
    int load_retval = load_selected_image(
        image_info,
        // 0x850 contains ILLB, 0x854 contains IBSS (no null terminator in between them)
        //0x854,
        // Try doing it the same way it's done in the source
        type,
        // Hard-coded in the boot ROM
        USB_RECV_REGION_BASE,
        loaded_length,
        1
    );
     */

    //int (*load_selected_image)(int image_addr, int type_tag, int load_addr, int loaded_length, int boot_flags) = (void*)load_selected_image_addr;
    int (*image_load)(struct image_info* image_info, int type_tag, int load_addr, int loaded_length) = (void*)0x749d;
    // r3 must be <= image_info->imageAllocation
    int load_retval = image_load(
        image_info,
        //type???
        // type or memory base?
        type,
        USB_RECV_REGION_BASE,
        loaded_length
    );

    /*
    image_load(
        struct image_info *image,
        const uint32_t *types,
        uint32_t count,
        uint32_t *actual,
        void **load_addr,
        size_t *load_len);
     */
    /*
    int load_retval = image_load(
        // struct image_info*
        image_info,
        &type,
        1,
    );
    */

    uint32_t* sentinel_buffer = (uint32_t*)SENTINEL_ADDRESS;
    sentinel_buffer[0] = 0xcafebabe;
    sentinel_buffer[1] = get_dfu_image_result;
    sentinel_buffer[2] = loaded_length;
    sentinel_buffer[3] = image_info;
    sentinel_buffer[4] = load_retval;

    // image_info->imageLength = 0x000109c4
    // image_info->imageAllocation = 0x000109c4
    // image_info->imageType = 0
    // image_info->imagePrivateMagic = 0x4d656d7a
    // image_info->imageOptions = 3
    sentinel_buffer[5] = image_info->imageLength;
    sentinel_buffer[6] = image_info->imageAllocation;
    sentinel_buffer[7] = image_info->imageType;
    sentinel_buffer[8] = image_info->imagePrivateMagic;
    sentinel_buffer[9] = image_info->imageOptions;

    memcpy(DUMP_TO, DUMP_FROM, DUMP_SIZE);

    /*
    char* mem = (char*)patch_cmp_instruction_addr;
    mem[0] = 0x80;
    mem[1] = 0x42;
    */
    jump_to(0, USB_RECV_REGION_BASE, 0);

    /*
    void (*entry_point)(int arg1, int arg2, int arg3, int arg4) = (void*)load_address;
    entry_point(0, 0, 0, 0);
     */
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
