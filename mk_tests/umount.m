#include <stddef.h>
#include <stdint.h>

#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>

int unmount(const char* path, int flags);
int printf(const char* fmt, ...);
int MKMakeDeviceBootable(const char* arg0);

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

/*
int main(int argc, const char** argv) {
	const char* path = argv[1];
	printf("Unmounting %s...\n", path);
	int ret = unmount(path, 0);
	printf("Return code %d\n", ret); 
	return 5;
}
*/

typedef void* MKMediaRef;
typedef int MKStatus;

void* try_symbol(const char* name) {
    void* libHandle = dlopen("/System/Library/PrivateFrameworks/MediaKit.framework/MediaKit", RTLD_NOW);
    printf("Trying to find %s...\n", name);
    void* sym = dlsym(libHandle, name);
    if (!sym) {
        printf("*** Failed to find %s!\n", name);
    }
    else {
        printf("Found %s: %p\n", name, sym);
    }
    return sym;
}

void redo_asr() {
    printf("Trying!\n");
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(
            kCFAllocatorDefault,
            2,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
    );
    printf("got dict %p!\n", options);
    CFDictionaryAddValue(options, @"Writable", kCFBooleanTrue);
    printf("added one option\n");
    // Maybe not needed?
    CFDictionaryAddValue(options, @"Shared Writer", kCFBooleanTrue);
    printf("added options\n");

    printf("trying to get symbol...\n");
    MKMediaRef (*MKMediaCreateWithPath)(CFAllocatorRef, const char* path, CFDictionaryRef, MKStatus*) = try_symbol("MKMediaCreateWithPath");

    MKStatus err = -1;
    MKMediaRef mediaRef = MKMediaCreateWithPath(
            kCFAllocatorDefault,
            "/dev/rdisk0s1",
            options,
            &err
    );
    printf("MKMediaCreateWithPath() returned %p\n", mediaRef);
    hexdump(mediaRef, 1024);

    /*
    int (*MKCFReadMedia)(const char*, MKMediaRef, CFMutableDictionaryRef) = try_symbol("MKCFReadMedia");
    int ret = MKCFReadMedia("/dev/rdisk0s1", mediaRef, options);
    printf("MKCFReadMedia() returned %p\n", ret);
     */
    int (*MKCFPrepareBootDevice)(MKMediaRef, int, int, int, int, int, int) = try_symbol("MKCFPrepareBootDevice");

    int ret = MKCFPrepareBootDevice("/dev/rdisk0", 0, 0, 0x00003000, 0, 0, 0);
    printf("MKCFPrepareBootDevice() returned %d\n", ret);
}

int main(int argc, const char** argv) {
    redo_asr();
    return 0;
    const char* path = argv[1];
    printf("Will attempt to call MKMakeDeviceBootable!\n");
    void* libHandle = dlopen("/System/Library/PrivateFrameworks/MediaKit.framework/MediaKit", RTLD_NOW);
    printf("LibHandle %p\n", libHandle);

    //void  *dlsym(void *__restrict__ handle, const char *__restrict__ name);
    int (*make_bootable)(const char* path) = dlsym(libHandle, "MKMakeDeviceBootable");
    printf("makeBootable = %p\n", make_bootable);
    /*
    int (*make_bootable2)(const char* path) = dlsym(libHandle, "MKCFPrepareBootDevice");
    printf("MKCFPrepareBootDevice = %p\n", make_bootable2);
    int ret = make_bootable2("/dev/disk0s1");
    printf("MKCFPrepareBootDevice() = %d\n", ret);
    */

    int (*MKMediaCreateWithPath)(CFAllocatorRef, const char* path, CFDictionaryRef, MKStatus*) = dlsym(libHandle, "MKMediaCreateWithPath");
    printf("Got MKMediaCreateWithPath %p\n", MKMediaCreateWithPath);
    MKStatus err = -1;
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    //CFDictionarySetValue(options, kMKMediaPropertyWritableKey, kCFBooleanTrue);
    MKMediaRef gpt_ref = MKMediaCreateWithPath(kCFAllocatorDefault, "/dev/disk0s1", options, &err);
    printf("Got gpt_ref = %p\n", gpt_ref);

    void* a = try_symbol("MKMakePartBootable");

    // Exists
    try_symbol("MKCFCheckBootDevice");

    // Exists
    try_symbol("PMSetBootPartition");

    int (*MKCFPrepareBootDevice)(void) = try_symbol("MKCFPrepareBootDevice");
    int ret = MKCFPrepareBootDevice();
    printf("MKCFPrepareBootDevice() = %d\n", ret);

    //int ret = MKMakeDeviceBootable("/dev/disk0s1");
    //int ret = make_bootable("/dev/disk0s1");
    //printf("Ret = %d\n", ret);
    return 0;
}

