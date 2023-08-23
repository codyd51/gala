#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <stdio.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <dispatch/dispatch.h>
#include <ImageIO/ImageIO.h>

void _CFAutoreleasePoolPush();

int spawn_in_background(const char* path, const char** argv) {
    int pid = fork();
    if (!pid) {
        char* envp[] = {NULL};
        if (execve(path, argv, envp) == -1) {
            printf("Failed to execve\n");
            return -1;
        }
        exit(1);
    }
    return pid;
}

int run_and_wait(const char* path, const char** argv) {
    int pid = spawn_in_background(path, argv);
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

bool does_file_exist(const char* path) {
    return access(path, F_OK) == 0;
}

void spin_until_file_appears(const char* path) {
    printf("Spinning until path appears: %s\n", path);
    while (true) {
        if (does_file_exist(path)) {
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
    return [[[PTVector alloc] initWithX:x Y:y] retain];
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
    return [[[PTEdge alloc] initWithVertex1:vertex1 vertex2:vertex2] retain];
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
@property CGContextRef display_cgcontext;
@property CGRect display_frame;
@property CGImageRef sprite_image;
@property CGImageRef active_image;
@property CGColorSpaceRef color_space;

@property (retain) NSArray* walls;

@property CGRect text_frame;

@property CGRect sprite_frame;
@property CGPoint icon_position;
@property (retain) PTVector* direction;
@property int sign_x;
@property int sign_y;
- (instancetype)init;
- (void)resetIconPosition;
- (void)step;
- (void)stepUntilFileAppears:(const char*)path;
@end

@implementation PTRestoreGui
- (instancetype)init {
    if ((self = [super init])) {
        IOMobileFramebufferRef framebuffer_ref;
        IOReturn io_retval = IOMobileFramebufferGetMainDisplay(&framebuffer_ref);
        if (io_retval != kIOReturnSuccess || !framebuffer_ref) {
            printf("Failed to get framebuffer\n");
            return nil;
        }
        printf("Got framebuffer %p\n", (void*)framebuffer_ref);

        IOSurfaceRef surface;
        CGColorSpaceRef color_space;
        self.display_cgcontext = get_display_cgcontext(framebuffer_ref, &surface, &color_space);
        self.color_space = color_space;
        printf("got context\n");

        size_t display_width = CGBitmapContextGetWidth(self.display_cgcontext);
        size_t display_height = CGBitmapContextGetHeight(self.display_cgcontext);
        self.display_frame = CGRectMake(0, 0, display_width, display_height);

        [self resetIconPosition];
        self.sprite_frame = CGRectMake(
                self.icon_position.x,
                self.icon_position.y,
                100,
                100
        );
        CGFloat sprite_width = CGRectGetWidth(self.sprite_frame);
        CGFloat sprite_height = CGRectGetHeight(self.sprite_frame);

        printf("getting images\n");
        [self setSpriteImageToImageAtPath:"/mnt2/gala/boot_logo.png"];
        [self setActiveImageToImageAtPath:"/mnt2/gala/mounting_dev_disk0s2s1.png"];
        printf("done getting images\n");

        CGSize text_size = CGSizeMake(display_width * 1.0, display_height * 0.1);
        self.text_frame = CGRectMake(
                (display_width / 2.0) - (text_size.width / 2.0),
                (display_height / 2.0) - (text_size.height / 2.0),
                text_size.width,
                text_size.height
        );
        //printf("text_frame %f %f, %f, %f\n", text_frame.origin.x, text_frame.origin.y, text_frame.size.width, text_frame.size.height);

        // TODO(PT): Only redraw the text if the apple logo overlaps with it?
        self.sign_x = 1;
        self.sign_y = 1;

        NSArray* edges_of_screen = [PTEdge edgesOfRect:self.display_frame];
        NSArray* edges_of_text = [PTEdge edgesOfRect:self.text_frame];
        NSMutableArray* walls = [NSMutableArray array];
        [walls addObjectsFromArray:edges_of_screen];
        self.walls = [NSArray arrayWithArray:walls];

        [walls release];
        [edges_of_text release];
        [edges_of_screen release];

        //printf("retain counts %d %d %d\n", walls.retainCount, edges_of_text.retainCount, edges_of_screen.retainCount);
        //[walls addObjectsFromArray:edges_of_text];
        // PT: Must be less than half the icon size...
        self.direction = [[[PTVector alloc] initWithX:40 Y:40] retain];
    }
    return self;
}

- (void)resetIconPosition {
    self.icon_position = CGPointMake(80, 80);
}
- (void)drawBackground {
    printf("drawing background\n");
    CGColorRef background_color = CGColorCreate(self.color_space, (CGFloat[]){164/255.0, 255/255.0, 125/255.0, 1});
    CGContextSetFillColorWithColor(self.display_cgcontext, background_color);
    CGContextFillRect(self.display_cgcontext, self.display_frame);

    CFRelease(background_color);
    printf("done drawing background\n");
}

- (CGImageRef)imageWithContentsOfPath:(const char*)path {
    if (!does_file_exist(path)) {
        printf("Expected image at %s, but the path doesn't exist!\n", path);
        exit(1);
    }
    CFURLRef image_path_url = CFURLCreateWithFileSystemPath(NULL, CFStringCreateWithCString(NULL, path, kCFStringEncodingASCII), kCFURLPOSIXPathStyle, NO);

    CFMutableDictionaryRef options = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(options, kCGImageSourceShouldCache, kCFBooleanTrue);
    CGImageSourceRef image_source = CGImageSourceCreateWithURL(image_path_url, options);
    CGImageRef image = CGImageSourceCreateImageAtIndex(image_source, 0, options);
    CGImageRef copiedImage = CGImageCreateCopy(image);

    CFRelease(image);
    CFRelease(image_source);
    CFRelease(options);
    CFRelease(image_path_url);
    return copiedImage;
}

- (void)step {
    CGColorRef background_color = CGColorCreate(self.color_space, (CGFloat[]){189/255.0, 255/255.0, 191/255.0, 1});
    //CGContextClearRect(display_cgcontext, display_frame);

    CGPoint previous_icon_position = self.icon_position;
    self.icon_position = CGPointMake(
        self.icon_position.x + (self.direction.x * self.sign_x),
        self.icon_position.y + (self.direction.y * self.sign_y)
    );

    // Check for collision with each of our walls
    for (PTEdge* edge in self.walls) {
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
            if (self.icon_position.y >= lower_y && self.icon_position.y < higher_y) {
                // 'Increasing' intersection
                if (previous_icon_position.x < edge.vertex1.x && self.icon_position.x + self.sprite_frame.size.width >= edge.vertex1.x) {
                    //printf("Increasing intersection on vertical wall\n");
                    detected_intersection = true;
                }
                    // 'Decreasing' intersection
                else if (previous_icon_position.x > edge.vertex1.x && self.icon_position.x <= edge.vertex1.x) {
                    //printf("Decreasing intersection on vertical wall\n");
                    detected_intersection = true;
                }
            }
        }
        else {
            // Is the sprite within the horizontal segment?
            if (self.icon_position.x >= lower_x && self.icon_position.x < higher_x) {
                // 'Increasing' intersection
                if (previous_icon_position.y < edge.vertex1.y && self.icon_position.y >= edge.vertex1.y) {
                    //printf("Increasing intersection on horizontal wall\n");
                    detected_intersection = true;
                }
                    // 'Decreasing' intersection
                else if (previous_icon_position.y > edge.vertex1.y && self.icon_position.y <= edge.vertex1.y) {
                    //printf("Decreasing intersection on horizontal wall\n");
                    detected_intersection = true;
                }
            }
        }

        if (detected_intersection) {
            PTVector* plane_normal = edge.normal2;
            CGFloat dot = [self.direction dot:plane_normal];

            PTVector* comp = [plane_normal multiply:-2.0 * dot];
            PTVector* resultant = [comp add:self.direction];
            self.direction.x = resultant.x;
            self.direction.y = resultant.y;

            [comp release];
            [resultant release];
            ///printf("edge (%f, %f) - (%f, %f)\n", edge.vertex1.x, edge.vertex1.y, edge.vertex2.x, edge.vertex2.y);
            //printf("new vector (%f %f) pos (%f %f)\n", direction.x, direction.y, icon_position.x, icon_position.y);
            break;
        }
    }

    // Failsafe, don't allow sprites to go off-screen
    if (self.icon_position.x < 0) self.icon_position = CGPointMake(1, self.icon_position.y);
    if (self.icon_position.y < 0) self.icon_position = CGPointMake(self.icon_position.x, 1);

    size_t display_width = CGBitmapContextGetWidth(self.display_cgcontext);
    size_t display_height = CGBitmapContextGetHeight(self.display_cgcontext);
    if (self.icon_position.x >= display_width) self.icon_position = CGPointMake(display_width - 1, self.icon_position.y);
    if (self.icon_position.y >= display_height) self.icon_position = CGPointMake(self.icon_position.x, display_height - 1);
    // Failsafe, don't allow velocity to go to zero
    if (self.direction.x == 0) self.direction.x = 10;
    if (self.direction.y == 0) self.direction.y = 10;

    self.sprite_frame = CGRectMake(self.icon_position.x, self.sprite_frame.origin.y, self.sprite_frame.size.width, self.sprite_frame.size.height);
    self.sprite_frame = CGRectMake(self.sprite_frame.origin.x, self.icon_position.y, self.sprite_frame.size.width, self.sprite_frame.size.height);
    CGContextDrawImage(self.display_cgcontext, self.sprite_frame, self.sprite_image);

    CGContextDrawImage(self.display_cgcontext, self.text_frame, self.active_image);
}

- (void)stepUntilFileAppears:(const char*)path {
    while (1) {
        [self step];
        usleep(100000);
        if (does_file_exist(path)) {
            break;
        }
    }
}

- (void)stepUntilProcessExits:(int)pid {
    while (1) {
        [self step];
        usleep(10000);
        int returned_pid = waitpid(pid, NULL, WNOHANG);
        if (returned_pid == pid) {
            // waitpid() only returns the PID of the process if the process has terminated
            break;
        }
    }
}

- (void)setActiveImageToImageAtPath:(const char*)path {
    // Important: if the previous image isn't released, then a file descriptor is retained, and we won't be able to
    // unmount /mnt2
    if (self.active_image) {
        CFRelease(self.active_image);
    }
    self.active_image = [self imageWithContentsOfPath:path];
}

- (void)setSpriteImageToImageAtPath:(const char*)path {
    // Important: if the previous image isn't released, then a file descriptor is retained, and we won't be able to
    // unmount /mnt2
    if (self.sprite_image) {
        CFRelease(self.sprite_image);
    }
    self.sprite_image = [self imageWithContentsOfPath:path];
}

@end

int main(int argc, const char** argv) {
    printf("*** asr_wrapper startup ***\n");

    _CFAutoreleasePoolPush();

    int ret = 0;
    printf("Mounting /mnt2...\n");
    const char *mount_path = "/sbin/mount_hfs";
    const char *mount_argv[] = {mount_path, "/dev/disk0s2s1", "/mnt2", NULL};
    ret = run_and_wait(mount_path, mount_argv);
    if (ret != 0) {
        printf("Mounting /dev/disk0s2s1 to /mnt2 failed\n");
        return -1;
    }

    mkdir("/mnt2/gala", 0700);
    FILE *fp = fopen("/mnt2/gala/sentinel__device_is_ready_for_host_to_send_image_assets", "a");
    fclose(fp);
    printf("Spinning until the host uploads images...\n");
    spin_until_file_appears("/mnt2/gala/sentinel__host_has_uploaded_image_assets");

    PTRestoreGui *gui = [[PTRestoreGui alloc] init];
    [gui drawBackground];
    [gui step];

    // Inform the host by creating a sentinel file
    printf("Creating sentinel file to ask the host to send the root filesystem...\n");
    fp = fopen("/mnt2/gala/sentinel__device_is_ready_for_host_to_send_rootfs" ,"a");
    fclose(fp);

    printf("Waiting for filesystem...");
    [gui drawBackground];
    [gui resetIconPosition];
    [gui setActiveImageToImageAtPath:"/mnt2/gala/receiving_filesystem_over_usb2.png"];
    [gui stepUntilFileAppears:"/mnt2/gala/sentinel__rootfs_is_fully_uploaded"];

    printf("Root filesystem is uploaded! Running asr...\n");
    [gui drawBackground];
    [gui resetIconPosition];
    [gui setActiveImageToImageAtPath:"/mnt2/gala/running_asr.png"];

    const char* asr_path = "/usr/sbin/asr";
    const char* asr_argv[] = {asr_path, "-source", "/mnt2/gala/root_filesystem.dmg", "-target", "/dev/disk0s1", "-erase", "-noprompt", NULL};
    int pid = spawn_in_background(asr_path, asr_argv);
    [gui stepUntilProcessExits:pid];

    printf("Unmounting /mnt2 to match what restored_external expects...\n");
    [gui drawBackground];
    [gui resetIconPosition];
    [gui setActiveImageToImageAtPath:"/mnt2/gala/unmounting.png"];
    [gui step];

    // Free the images, so we can free up the extant file descriptors and unmount the Data partition
    CFRelease(gui.active_image);
    CFRelease(gui.sprite_image);

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
