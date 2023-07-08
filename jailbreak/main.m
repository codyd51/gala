//
//  main.m
//  jailbreak
//
//  Created by Phillip Tennen on 08/07/2023.
//

#import <Foundation/Foundation.h>
#import <IOKit/usb/IOUSBLib.h>
#import <libusb-1.0/libusb.h>

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

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        NSLog(@"Hello, World!");
        
        // Signal handler to respond to kill requests
        sig_t old_handler = signal(SIGINT, handle_sigint_received);
        if (old_handler == SIG_ERR) {
            NSLog(@"Couldn't establish a new SIGINT handler");
            exit(1);
        }
        assert(old_handler != SIG_ERR);
        
        CFMutableDictionaryRef match_usb_devices = IOServiceMatching(kIOUSBDeviceClassName);
        if (!match_usb_devices) {
            NSLog(@"Failed to create a match dict");
            exit(1);
        }
        
        // Asynchronously notify us when a USB event occurs
        IONotificationPortRef notify_port = IONotificationPortCreate(kIOMainPortDefault);
        CFRunLoopSourceRef run_loop_source = IONotificationPortGetRunLoopSource(notify_port);
        
        CFRunLoopRef run_loop = CFRunLoopGetCurrent();
        CFRunLoopAddSource(run_loop, run_loop_source, kCFRunLoopDefaultMode);
        
        // Set up a notification for when a device is first matched by IOKit
        io_iterator_t device_added_iterator;
        kern_return_t ret = IOServiceAddMatchingNotification(notify_port,
                                                             kIOFirstMatchNotification,
                                                             match_usb_devices,
                                                             handle_device_added,
                                                             NULL,
                                                             &device_added_iterator);
        
        // Iterate once to get the devices that were present before this process began
        handle_device_added(NULL, device_added_iterator);
        
        // Start the run loop to start receiving notifications
        CFRunLoopRun();
    }
    
    // We should only exit from the signal handler
    NSLog(@"Shouldn't be reachable...");
    exit(1);
}
