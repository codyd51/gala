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
#include <ImageIO/ImageIO.h>

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

CGContextRef get_display_cgcontext(IOMobileFramebufferRef framebuffer_ref, IOSurfaceRef* out_surface, CGColorSpaceRef* out_color_space) {
    CGSize display_size;
    if (IOMobileFramebufferGetDisplaySize(framebuffer_ref, &display_size) != kIOReturnSuccess) {
        printf("Failed to get display size\n");
        return NULL;
    }
    printf("Display size: (%f, %f)\n", display_size.width, display_size.height);
    int screen_width = (int)display_size.width;
    int screen_height = (int)display_size.height;

    IOReturn io_retval = IOMobileFramebufferGetLayerDefaultSurface(
            framebuffer_ref,
            0,
            out_surface
    );

    size_t stride = IOSurfaceGetBytesPerRow(*out_surface);
    *out_color_space = CGColorSpaceCreateDeviceRGB();
    void* base = IOSurfaceGetBaseAddress(*out_surface);

    CGContextRef context = CGBitmapContextCreate(
        IOSurfaceGetBaseAddress(*out_surface),
        (int)display_size.width,
        (int)display_size.height,
        8,
        stride,
        *out_color_space,
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
    return (self.x * other.x) + (self.y * other.y);
}

- (instancetype)multiply:(CGFloat)scalar {
    return [PTVector vectorWithX:self.x * scalar Y:self.y * scalar];
}

- (instancetype)add:(PTVector*)other {
    return [PTVector vectorWithX:self.x + other.x Y:self.y + other.y];
}
@end

@interface PTEdge : NSObject
@property CGPoint vertex1;
@property CGPoint vertex2;
@property (retain) PTVector* normal1;
@property (retain) PTVector* normal2;
+ (instancetype)edgeWithVertex1:(CGPoint)vertex1 vertex2:(CGPoint)vertex2;
+ (NSArray*)edgesOfRect:(CGRect)rect;
- (instancetype)initWithVertex1:(CGPoint)vertex1 vertex2:(CGPoint)vertex2;
@end

@implementation PTEdge
+ (instancetype)edgeWithVertex1:(CGPoint)vertex1 vertex2:(CGPoint)vertex2 {
    return [[PTEdge alloc] initWithVertex1:vertex1 vertex2:vertex2];
}

+ (NSArray*)edgesOfRect:(CGRect)rect {
    CGFloat min_x = CGRectGetMinX(rect);
    CGFloat min_y = CGRectGetMinY(rect);
    CGFloat max_x = CGRectGetMaxX(rect);
    CGFloat max_y = CGRectGetMaxY(rect);
    return @[
        // Top edge
        [PTEdge edgeWithVertex1:CGPointMake(min_x, max_y) vertex2:CGPointMake(max_x, max_y)],
        // Right edge
        [PTEdge edgeWithVertex1:CGPointMake(max_x, max_y) vertex2:CGPointMake(max_x, min_y)],
        // Bottom edge
        [PTEdge edgeWithVertex1:CGPointMake(min_x, min_y) vertex2:CGPointMake(max_x, min_y)],
        // Left edge
        [PTEdge edgeWithVertex1:CGPointMake(min_x, max_y) vertex2:CGPointMake(min_x, min_y)],
    ];
}

- (instancetype)initWithVertex1:(CGPoint)vertex1 vertex2:(CGPoint)vertex2 {
    if ((self = [super init])) {
        self.vertex1 = vertex1;
        self.vertex2 = vertex2;
        CGFloat dx = self.vertex2.x - self.vertex1.x;
        CGFloat dy = self.vertex2.y - self.vertex1.y;

        //PTVector* normal1 = [PTVector]
        // Normalize the normals to the unit length
        if (dx != 0) {
            dx = dx / dx;
        }
        if (dy != 0) {
            dy = dy / dy;
        }
        printf("dx %f dy %f\n", dx, dy);
        self.normal1 = [PTVector vectorWithX:-dy Y:dx];
        self.normal2 = [PTVector vectorWithX:dy Y:-dx];

    }
    return self;
}
@end

@interface PTRestoreGui : NSObject
@property CFImageRef activeImage;
- (instancetype)init;
@end

@implementation PTRestoreGui
- (instancetype)init {
    if ((self = [super init])) {

    }
    return self;
}
@end

int main(int argc, const char** argv) {
    printf("*** asr_wrapper startup ***\n");

    //set_display_first();
    IOMobileFramebufferRef framebuffer_ref;
    IOReturn io_retval = IOMobileFramebufferGetMainDisplay(&framebuffer_ref);
    if (io_retval != kIOReturnSuccess || !framebuffer_ref) {
        printf("Failed to get framebuffer\n");
        return 1;
    }
    printf("Got framebuffer %p\n", (void*)framebuffer_ref);

    IOSurfaceRef surface;
    CGColorSpaceRef color_space;
    CGContextRef display_cgcontext = get_display_cgcontext(framebuffer_ref, &surface, &color_space);

    size_t display_width = CGBitmapContextGetWidth(display_cgcontext);
    size_t display_height = CGBitmapContextGetHeight(display_cgcontext);
    CGRect display_frame = CGRectMake(0, 0, display_width, display_height);

    CGPoint icon_position = CGPointMake(80, 80);
    CGRect sprite_frame = CGRectMake(
            icon_position.x,
            icon_position.y,
            100,
            100
    );
    CGFloat sprite_width = CGRectGetWidth(sprite_frame);
    CGFloat sprite_height = CGRectGetHeight(sprite_frame);

    CFURLRef sprite_image_path_url = CFURLCreateWithFileSystemPath(NULL, CFStringCreateWithCString(NULL, "/boot_logo.png", kCFStringEncodingASCII), kCFURLPOSIXPathStyle, NO);
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CGImageSourceRef sprite_image_source = CGImageSourceCreateWithURL(sprite_image_path_url, options);
    CGImageRef sprite_image = CGImageSourceCreateImageAtIndex(sprite_image_source, 0, options);

    CFURLRef image_path_url = CFURLCreateWithFileSystemPath(NULL, CFStringCreateWithCString(NULL, "/receiving_filesystem_over_usb2.png", kCFStringEncodingASCII), kCFURLPOSIXPathStyle, NO);
    CGImageSourceRef image_source = CGImageSourceCreateWithURL(image_path_url, options);
    CGImageRef image = CGImageSourceCreateImageAtIndex(image_source, 0, options);
    CGSize text_size = CGSizeMake(display_width * 0.6, display_height * 0.15);
    CGRect text_frame = CGRectMake(
            (display_width / 2.0) - (text_size.width / 2.0),
            (display_height / 2.0) - (text_size.height / 2.0),
            text_size.width,
            text_size.height
    );
    printf("text_frame %f %f, %f, %f\n", text_frame.origin.x, text_frame.origin.y, text_frame.size.width, text_frame.size.height);

    int sign_x = 1;
    int sign_y = 1;

    NSArray* edges_of_screen = [PTEdge edgesOfRect:display_frame];
    NSArray* edges_of_text = [PTEdge edgesOfRect:text_frame];
    NSMutableArray* walls = [NSMutableArray array];
    [walls addObjectsFromArray:edges_of_screen];
    //[walls addObjectsFromArray:edges_of_text];
    // PT: Must be less than half the icon size...
    PTVector* direction = [[PTVector alloc] initWithX:10 Y:10];

    CGColorRef background_color = CGColorCreate(color_space, (CGFloat[]){164/255.0, 255/255.0, 125/255.0, 1});
    CGContextSetFillColorWithColor(display_cgcontext, background_color);
    CGContextFillRect(display_cgcontext, display_frame);

    while (1) {
        //IOSurfaceLock(surface, 0, 0);

        //CGColorRef background_color = CGColorCreate(color_space, (CGFloat[]){189/255.0, 255/255.0, 191/255.0, 1});
        //CGContextClearRect(display_cgcontext, display_frame);

        CGPoint previous_icon_position = icon_position;
        icon_position.x += direction.x * sign_x;
        icon_position.y += direction.y * sign_y;

        // Check for collision with each of our walls
        for (PTEdge* edge in walls) {
            CGFloat lower_y = MIN(edge.vertex1.y, edge.vertex2.y);
            CGFloat higher_y = MAX(edge.vertex1.y, edge.vertex2.y);

            CGFloat lower_x = MIN(edge.vertex1.x, edge.vertex2.x);
            CGFloat higher_x = MAX(edge.vertex1.x, edge.vertex2.x);

            // Did we just cross into the wall?
            bool detected_intersection = false;
            // First, check whether we're dealing with a horizontal or vertical wall
            bool is_wall_vertical = edge.vertex1.x == edge.vertex2.x;
            if (is_wall_vertical) {
                // Is the sprite within the vertical segment?
                if (icon_position.y >= lower_y && icon_position.y < higher_y) {
                    // 'Increasing' intersection
                    if (previous_icon_position.x < edge.vertex1.x && icon_position.x + sprite_width >= edge.vertex1.x) {
                        printf("Increasing intersection on vertical wall\n");
                        detected_intersection = true;
                    }
                    // 'Decreasing' intersection
                    else if (previous_icon_position.x > edge.vertex1.x && icon_position.x <= edge.vertex1.x) {
                        printf("Decreasing intersection on vertical wall\n");
                        detected_intersection = true;
                    }
                }
            }
            else {
                // Is the sprite within the horizontal segment?
                if (icon_position.x >= lower_x && icon_position.x < higher_x) {
                    // 'Increasing' intersection
                    if (previous_icon_position.y < edge.vertex1.y && icon_position.y >= edge.vertex1.y) {
                        printf("Increasing intersection on horizontal wall\n");
                        detected_intersection = true;
                    }
                    // 'Decreasing' intersection
                    else if (previous_icon_position.y > edge.vertex1.y && icon_position.y <= edge.vertex1.y) {
                        printf("Decreasing intersection on horizontal wall\n");
                        detected_intersection = true;
                    }
                }
            }

            if (detected_intersection) {
                PTVector* plane_normal = edge.normal2;
                CGFloat dot = [direction dot:plane_normal];

                PTVector* component = [plane_normal multiply:-2.0 * dot];
                PTVector* resultant = [[plane_normal multiply:-2.0 * dot] add:direction];

                direction.x = resultant.x;
                direction.y = resultant.y;

                printf("edge (%f, %f) - (%f, %f)\n", edge.vertex1.x, edge.vertex1.y, edge.vertex2.x, edge.vertex2.y);
                printf("new vector (%f %f) pos (%f %f)\n", direction.x, direction.y, icon_position.x, icon_position.y);
                break;
            }
        }

        // Failsafe, don't allow sprites to go off-screen
        if (icon_position.x < 0) icon_position.x = 1;
        if (icon_position.y < 0) icon_position.y = 1;
        if (icon_position.x >= display_width) icon_position.x = display_width - 1;
        if (icon_position.y >= display_height) icon_position.y = display_height - 1;
        // Failsafe, don't allow velocity to go to zero
        if (direction.x == 0) direction.x = 10;
        if (direction.y == 0) direction.y = 10;

        sprite_frame.origin.x = icon_position.x;
        sprite_frame.origin.y = icon_position.y;
        CGContextDrawImage(display_cgcontext, sprite_frame, sprite_image);

        CGContextDrawImage(display_cgcontext, text_frame, image);

        usleep(5000);
    }

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
