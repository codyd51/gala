#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <stdio.h>

#include <unistd.h>
#include <sys/wait.h>

#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <dispatch/dispatch.h>

int unmount(const char* path, int flags);
int printf(const char* fmt, ...);

int run_and_wait(const char* path, const char** argv) {
    int pid = fork();
    if (!pid) {
        char* envp[] = {NULL};
        if (execve(path, argv, envp) == -1) {
            printf("Failed to execve\n");
            return -1;
        }
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

void spin_until_file_appears(const char* path) {
    printf("Spinning until path appears: %s\n", path);
    const char* remote_path_start = "root@localhost:";

    while (true) {
        if (access(path, F_OK) == 0) {
            printf("File appeared! %s\n", path);
            return;
        }
        else {
            int delay_seconds = 5;
            printf("File hasn't appeared yet, will wait %d seconds...\n", delay_seconds);
            sleep(delay_seconds);
        }
    }
}

#include <mach/mach.h>

#define kIOReturnSuccess KERN_SUCCESS

const mach_port_t kIOMasterPortDefault;
typedef kern_return_t IOReturn;

typedef mach_port_t io_object_t;
typedef io_object_t io_iterator_t;
typedef io_object_t io_service_t;
typedef io_object_t io_registry_entry_t;
typedef char io_name_t[128];
typedef char io_string_t[512];

typedef struct __IOSurface *IOSurfaceRef;

CFMutableDictionaryRef IOServiceMatching(const char* name);

kern_return_t IOServiceGetMatchingServices(
    mach_port_t	mainPort,
    CFDictionaryRef	matching,
    io_iterator_t* existing
);
io_object_t IOIteratorNext(io_iterator_t iterator);
kern_return_t IORegistryEntryGetName(
    io_registry_entry_t	entry,
    io_name_t name
);
kern_return_t IOObjectGetClass(
    io_object_t	object,
    io_name_t className
);

io_registry_entry_t IORegistryEntryFromPath(
    mach_port_t	mainPort,
    const io_string_t path
);

typedef uint32_t IOSurfaceLockOptions;
void* IOSurfaceGetBaseAddress(IOSurfaceRef buffer);
size_t IOSurfaceGetBytesPerRow(IOSurfaceRef ref);
kern_return_t IOSurfaceLock(IOSurfaceRef buffer, IOSurfaceLockOptions options, uint32_t *seed);
kern_return_t IOSurfaceUnlock(IOSurfaceRef buffer, IOSurfaceLockOptions options, uint32_t *seed);

typedef struct __IOMobileFramebuffer *IOMobileFramebufferRef;
IOReturn IOMobileFramebufferGetMainDisplay(IOMobileFramebufferRef*);
IOReturn IOMobileFramebufferOpen(
    io_service_t service,
    task_port_t owningTask,
    unsigned int type,
    IOMobileFramebufferRef *pointer
);

IOReturn IOMobileFramebufferGetDisplaySize(
    IOMobileFramebufferRef pointer,
    CGSize *size
);
IOReturn IOMobileFramebufferGetLayerDefaultSurface(
    IOMobileFramebufferRef pointer,
    int surface,
    IOSurfaceRef* buffer
);

void set_display_first(void) {
    CFMutableDictionaryRef match_framebuf_dict = IOServiceMatching("IOMobileFramebuffer");
    io_iterator_t framebuffer_iterator;
    IOReturn io_retval = IOServiceGetMatchingServices(
        kIOMasterPortDefault,
        match_framebuf_dict,
        &framebuffer_iterator
    );
    if (io_retval != kIOReturnSuccess) {
        printf("Failed to get matching service\n");
        return;
    }
    printf("Succeeded to get service\n");

    io_service_t framebuffer_service;
    while ((framebuffer_service = IOIteratorNext(framebuffer_iterator))) {
        printf("Got framebuffer service 0x%08x\n", framebuffer_service);
        io_name_t service_name;
        io_retval = IORegistryEntryGetName(framebuffer_service, service_name);
        if (io_retval != kIOReturnSuccess) {
            printf("Failed to get framebuffer service name, skipping\n");
            continue;
        }
        printf("Framebuffer service name: %s\n", service_name);

        io_name_t class_name;
        io_retval = IOObjectGetClass(framebuffer_service, class_name);
        if (io_retval != kIOReturnSuccess) {
            printf("Failed to get framebuffer service class, skipping\n");
            continue;
        }
        printf("Framebuffer service class: %s\n", class_name);

        if (!strstr(class_name, "CLCD")) {
            printf("This service isn't AppleCLCD, will keep searching\n");
            continue;
        }

        IOMobileFramebufferRef framebuffer_ref;
        /*j
        io_retval = IOMobileFramebufferOpen(
            framebuffer_service,
            mach_task_self(),
            0,
            &framebuffer_ref
        );
         */
        IOReturn IOMobileFramebufferGetMainDisplay(IOMobileFramebufferRef*);
        io_retval = IOMobileFramebufferGetMainDisplay(&framebuffer_ref);

        if (io_retval != kIOReturnSuccess || !framebuffer_ref) {
            printf("Failed to get framebuffer\n");
            continue;
        }

        printf("Got framebuffer 0x%08x\n", framebuffer_ref);

        CGSize display_size;
        if (IOMobileFramebufferGetDisplaySize(framebuffer_ref, &display_size) != kIOReturnSuccess) {
            printf("Failed to get display size\n");
            continue;
        }
        printf("Display size: (%f, %f)\n", display_size.width, display_size.height);

        //io_service_t service = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
        int display_scale = 2;
        int display_rotation = 0;

        IOSurfaceRef surface;
        io_retval = IOMobileFramebufferGetLayerDefaultSurface(
            framebuffer_ref,
            0,
            &surface
        );

        /*
        CFStringRef keys[3];
        CFTypeRef values[3];

        keys[0] = kIOSurfaceIsGlobal;
        values[0] = kCFBooleanTrue;
        keys[1] = kIOSurfaceBytesPerRow;
        values[1] = kCFBooleanTrue;

        CFDictionaryRef dict = CFDictionaryCreate(NULL, (void **)keys, (void **)values, 3, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);


        if (io_retval != kIOReturnSuccess) {
            printf("Failed to get surface\n");
            continue;
        }
         */

        /*
        const CFStringRef kIOSurfaceIsGlobal;
        const CFStringRef kIOSurfaceBytesPerRow;
        const CFStringRef kIOSurfaceBytesPerElement;
        const CFStringRef kIOSurfaceWidth;
        const CFStringRef kIOSurfaceHeight;
        const CFStringRef kIOSurfacePixelFormat;
        const CFStringRef kIOSurfaceAllocSize;
        const CFStringRef kIOSurfaceMemoryRegion;

        int width = (int)display_size.width;
        int height = (int)display_size.height;

        int pitch = width * 4, allocSize = 4 * width * height;
        int bPE = 4;
        char pixelFormat[4] = {'A', 'R', 'G', 'B'};
        CFMutableDictionaryRef dict;
        dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                         &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(dict, kIOSurfaceIsGlobal, kCFBooleanTrue);
        //CFDictionarySetValue(dict, kIOSurfaceMemoryRegion, (CFStringRef)@"PurpleEDRAM");
        CFDictionarySetValue(dict, kIOSurfaceMemoryRegion, );
        CFDictionarySetValue(dict, kIOSurfaceBytesPerRow,
                             CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &pitch));
        CFDictionarySetValue(dict, kIOSurfaceBytesPerElement,
                             CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bPE));
        CFDictionarySetValue(dict, kIOSurfaceWidth,
                             CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &width));
        CFDictionarySetValue(dict, kIOSurfaceHeight,
                             CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &height));
        CFDictionarySetValue(dict, kIOSurfacePixelFormat,
                             CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, pixelFormat));
        CFDictionarySetValue(dict, kIOSurfaceAllocSize,
                             CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &allocSize));

        IOSurfaceRef IOSurfaceCreate(CFMutableDictionaryRef dict);
        IOSurfaceRef surface = IOSurfaceCreate(dict);
         */

        printf("Got surface %p\n", surface);

        IOReturn CoreSurfaceBufferLock(IOSurfaceRef ref, int arg2);
        io_retval = CoreSurfaceBufferLock(surface, 3);
        printf("CoreSurfaceBufferLock = %d\n", io_retval);

        CGContextRef CGBitmapContextCreate(void *data, size_t width, size_t height, size_t bitsPerComponent, size_t bytesPerRow, CGColorSpaceRef space, uint32_t bitmapInfo);
        //CGColorSpaceRef color_space = CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB);
        /*
        CGColorSpaceRef color_space = CGColorSpaceCreateDeviceRGB();
        CGContextRef context = CGBitmapContextCreate(
            IOSurfaceGetBaseAddress(surface),
            (int)display_size.width,
            (int)display_size.height,
            32,
            (int)display_size.width * 4,
            color_space,
            kCGBitmapAlphaInfoMask |
            kCGBitmapByteOrderDefault
        );
         */
        size_t stride = IOSurfaceGetBytesPerRow(surface);
        CGColorSpaceRef rgb = CGColorSpaceCreateDeviceRGB();
        void* base = IOSurfaceGetBaseAddress(surface);

        //IOSurfaceLock(surface, 0, nil);
        printf("base %p\n", base);
        memset(base, 0xff, 640*960*3);

        CGContextRef context = CGBitmapContextCreate(
            IOSurfaceGetBaseAddress(surface),
            (int)display_size.width,
            (int)display_size.height,
            8,
            stride,
            rgb,
            kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Host
        );

        CGContextSetLineWidth(context, 2); // set the line width
        CGContextSetRGBStrokeColor(context, 20.0 /255, 101.0 / 255.0, 18.0 / 255.0, 1.0);

        CGContextSetRGBFillColor(context, 0.5, 1, 0.8, 1);
        CGContextFillRect(context, CGRectMake(20, 40, 400, 600));

        CGPoint center = CGPointMake(display_size.width / 2, display_size.height / 2); // get the circle centre
        CGFloat radius = 0.9 * center.x; // little scaling needed
        CGFloat startAngle = -((float)M_PI / 2); // 90 degrees
        CGFloat endAngle = ((2 * (float)M_PI) + startAngle);
        CGContextAddArc(context, center.x, center.y, radius + 4, startAngle, endAngle, 0); // create an arc the +4 just adds some pixels because of the polygon line thickness
        CGContextStrokePath(context); // draw

        //IOMobileFramebufferReturn IOMobileFramebufferSwapSetLayer(IOMobileFramebufferConnection connection, int layerid, IOSurfaceRef buffer);
        IOReturn IOMobileFramebufferSwapBegin(IOMobileFramebufferRef connection, int *token);
        IOReturn IOMobileFramebufferSwapSetLayer(IOMobileFramebufferRef connection, int layerid, IOSurfaceRef buffer);
        IOReturn IOMobileFramebufferSwapWait(IOMobileFramebufferRef connection, int token, int something);
        IOReturn IOMobileFramebufferSwapEnd(IOMobileFramebufferRef connection);

        IOReturn IOMobileFramebufferWaitSurface(IOMobileFramebufferRef connection, IOSurfaceRef buf);
        /*
        io_retval = IOMobileFramebufferWaitSurface(framebuffer_ref, surface);
        printf("IOMobileFramebufferWaitSurface %p\n", framebuffer_ref);
         */

        int token = 123;
        io_retval = IOMobileFramebufferSwapBegin(framebuffer_ref, 0);
        printf("SwapBegin Got retval %d token %d\n", io_retval, token);

        int IOSurfaceGetID(IOSurfaceRef);
        int layerId = IOSurfaceGetID(surface);
        printf("layerId %d\n", layerId);
        io_retval = IOMobileFramebufferSwapSetLayer(framebuffer_ref, 0, surface);
        printf("SwapSetLayer retval = %d\n", io_retval);
        io_retval = IOMobileFramebufferSwapSetLayer(framebuffer_ref, 1, surface);
        printf("SwapSetLayer retval = %d\n", io_retval);
        io_retval = IOMobileFramebufferSwapSetLayer(framebuffer_ref, 2, surface);
        //io_retval = IOMobileFramebufferSwapSetLayer(framebuffer_ref, -1, surface);
        printf("SwapSetLayer retval = %d\n", io_retval);

        //io_retval = IOMobileFramebufferSwapWait(framebuffer_ref, token, 0);
        printf("SwapWait retval = %d\n", io_retval);

        io_retval = IOMobileFramebufferSwapEnd(framebuffer_ref);

        printf("retval = %d, token = %d\n", io_retval, token);

        /*
        io_retval = IOMobileFramebufferSwapSetLayer(framebuffer_ref, 0, surface);
        printf("retval = %d\n", io_retval);
         */

        //io_retval = IOMobileFramebufferSwapSetLayer(framebuffer_ref, token, surface);
        printf("retval = %d\n", io_retval);

        int i = 0;
        while (1) {
        //for (int i = 0; i < 3000; i++) {
            CGFloat radius = 20.0f + 4.0f * (i % 100);
            CGFloat angle = i * 1.1;
            CGPoint circleCenter = { 150 + radius * cos(angle), 100 + radius * sin(angle) };
            CGFloat circleRadius = 20;
            CGContextSetRGBFillColor(context, 0, (arc4random() % 40) / 40.0, 1 - (i % 2), 1);
            CGContextFillEllipseInRect(context, CGRectMake(circleCenter.x - circleRadius, circleCenter.y - circleRadius, circleRadius * 2, circleRadius * 2));
            i += 1;
        }

        //CGContextFlush(context);
        //IOSurfaceUnlock(surface, 0, 0);

        break;
    }
}

CGContextRef get_display_cgcontext(void) {
    IOMobileFramebufferRef framebuffer_ref;
    IOReturn io_retval = IOMobileFramebufferGetMainDisplay(&framebuffer_ref);

    if (io_retval != kIOReturnSuccess || !framebuffer_ref) {
        printf("Failed to get framebuffer\n");
        return NULL;
    }
    printf("Got framebuffer %p\n", (void*)framebuffer_ref);

    CGSize display_size;
    if (IOMobileFramebufferGetDisplaySize(framebuffer_ref, &display_size) != kIOReturnSuccess) {
        printf("Failed to get display size\n");
        return NULL;
    }
    printf("Display size: (%f, %f)\n", display_size.width, display_size.height);
    int screen_width = (int)display_size.width;
    int screen_height = (int)display_size.height;

    IOSurfaceRef surface;
    io_retval = IOMobileFramebufferGetLayerDefaultSurface(
            framebuffer_ref,
            0,
            &surface
    );

    size_t stride = IOSurfaceGetBytesPerRow(surface);
    CGColorSpaceRef rgb = CGColorSpaceCreateDeviceRGB();
    void* base = IOSurfaceGetBaseAddress(surface);

    CGContextRef context = CGBitmapContextCreate(
        IOSurfaceGetBaseAddress(surface),
        (int)display_size.width,
        (int)display_size.height,
        8,
        stride,
        rgb,
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Host
    );
    return context;
}

@interface PTVector : NSObject
@property CGFloat x;
@property CGFloat y;
+ (instancetype)vectorWithX:(CGFloat)x Y:(CGFloat)y;
- (instancetype)initWithX:(CGFloat)x Y:(CGFloat)y;
- (CGFloat)magnitude;
- (CGFloat)dot:(PTVector*)other;
- (instancetype)multiply:(CGFloat)scalar;
- (instancetype)add:(PTVector*)other;
@end

@implementation PTVector
+ (instancetype)vectorWithX:(CGFloat)x Y:(CGFloat)y {
    return [[PTVector alloc] initWithX:x Y:y];
}

- (instancetype)initWithX:(CGFloat)x Y:(CGFloat)y {
    if ((self = [super init])) {
        self.x = x;
        self.y = y;
    }
    return self;
}

- (CGFloat)magnitude {
    return sqrt(pow(self.x, 2) + pow(self.y, 2));
}

- (CGFloat)dot:(PTVector*)other {
    PTVector* v1 = self;
    PTVector* v2 = other;

    /*
    CGFloat m1 = [v1 magnitude];
    CGFloat m2 = [v2 magnitude];
     */

    CGFloat dot = (v1.x * v2.x) + (v1.y * v2.y);
    return dot;
    //return [[PTVector vectorWithX:]
}

- (instancetype)multiply:(CGFloat)scalar {
    return [PTVector vectorWithX:self.x * scalar Y:self.y * scalar];
}

- (instancetype)add:(PTVector*)other {
    return [PTVector vectorWithX:self.x + other.x Y:self.y + other.y];
}
@end

int main(int argc, const char** argv) {
    printf("*** asr_wrapper startup ***\n");

    //set_display_first();
    CGContextRef display_cgcontext = get_display_cgcontext();
    size_t display_width = CGBitmapContextGetWidth(display_cgcontext);
    size_t display_height = CGBitmapContextGetHeight(display_cgcontext);
    CGRect display_frame = CGRectMake(0, 0, display_width, display_height);

    CGPoint icon_position = CGPointMake(
        CGRectGetMidX(display_frame),
        CGRectGetMidY(display_frame)
    );

    int sign_x = 1;
    int sign_y = 1;

    /*
    CGFloat direction_x = 5;
    CGFloat direction_y = 5;
     */
    PTVector* direction = [[PTVector alloc] initWithX:5 Y:5];
    while (1) {
        CGContextClearRect(display_cgcontext, display_frame);

        CGContextSetRGBFillColor(
                display_cgcontext,
                1,
                0.2,
                0.2,
                1
        );

        icon_position.x += direction.x * sign_x;
        icon_position.y += direction.y * sign_y;

        // Did we hit the right edge of the screen?
        if (icon_position.x >= CGRectGetMaxX(display_frame)) {
            PTVector* plane_normal = [[PTVector alloc] initWithX:-1 Y:0];
            printf("plane_normal %f %f\n", plane_normal.x, plane_normal.y);
            CGFloat dot = [direction dot:plane_normal];
            printf("dot %f\n", dot);

            PTVector* component = [plane_normal multiply:-2.0 * dot];
            printf("component %f %f\n", component.x, component.y);
            PTVector* resultant = [[plane_normal multiply:-2.0 * dot] add:direction];

            direction.x = resultant.x;
            direction.y = resultant.y;
            printf("Got new resultant %f %f\n", resultant.x, resultant.y);
        }

        // Did we hit the left edge of the screen?
        if (icon_position.x < 0) {
            printf("Hit left edge\n");
            sign_x = 1;
            direction.x = (arc4random() % 10) / 2;
            printf("new direction_x = %f\n", direction.x);
        }

        // Did we hit the bottom edge of the screen?
        if (icon_position.y >= CGRectGetMaxY(display_frame)) {
            printf("Hit bottom edge\n");
            sign_y = -1;
            direction.y = (arc4random() % 10) / 2;
            printf("new direction_y = %f\n", direction.y);
        }

        // Did we hit the top edge of the screen?
        if (icon_position.y < 0) {
            printf("Hit top edge\n");
            sign_y = 1;
            direction.y = (arc4random() % 10) / 2;
            printf("new direction_y = %f\n", direction.y);
        }

        CGContextFillRect(
            display_cgcontext,
            CGRectMake(
                    icon_position.x,
                    icon_position.y,
                    30,
                    30
            )
        );
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        //  your code
        while (true) {
            printf("Background thread!\n");
            sleep(1);
        }
    });

    dispatch_async(dispatch_get_main_queue(), ^{
        while (true) {
            printf("Main thread!\n");
            sleep(1);
        }
    });

    dispatch_main();
    
    while (true) {
        printf("Main thread!\n");
        sleep(1);
    }
    return 0;

    printf("Mounting /mnt2...\n");
    const char* mount_path = "/sbin/mount_hfs";
    const char* mount_argv[] = {mount_path, "/dev/disk0s2s1", "/mnt2", NULL};
    int ret = run_and_wait(mount_path, mount_argv);
    if (ret != 0) {
        printf("Mounting /dev/disk0s2s1 to /mnt2 failed\n");
        return -1;
    }

    // Inform the host by creating a sentinel file
    // touch /mnt2/sentinel__device_is_ready_for_host_to_send_rootfs
    printf("Creating sentinel file to ask the host to send the root filesystem...\n");
    FILE* fp = fopen("/mnt2/sentinel__device_is_ready_for_host_to_send_rootfs" ,"a");
    fclose(fp);

    spin_until_file_appears("/mnt2/sentinel__rootfs_is_fully_uploaded");

    printf("Root filesystem is uploaded!\n");
    const char* asr_path = "/usr/sbin/asr";
    const char* asr_argv[] = {asr_path, "-source", "/mnt2/root_filesystem.dmg", "-target", "/dev/disk0s1", "-erase", "-noprompt", NULL};
    ret = run_and_wait(asr_path, asr_argv);
    printf("asr ret = %d\n", ret);

    printf("Unmounting /mnt2 to match what restored_external expects...\n");
    const char* umount_path = "/usr/bin/umount";
    const char* umount_argv[] = {umount_path, "/mnt2", NULL};
    ret = run_and_wait(umount_path, umount_argv);
    if (ret != 0) {
        printf("Unmounting the Data partition failed!\n");
        return -1;
    }

    printf("asr_wrapper is done!\n");
    return 0;
}
