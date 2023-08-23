#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#include <stdio.h>

#include <unistd.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>         //exit
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <memory.h>

#define LONG *(volatile unsigned long*)

/* read from virtual memory */
int read_kmem(off_t offset, void* buf, size_t count)
{
    int fd;
    int n;

    fd = open("/dev/kmem", O_RDONLY);
    if (fd < 0)
    {
        perror("open /dev/kmem failed");
        return -1;
    }

    lseek(fd, offset, SEEK_SET);
    n = read(fd, buf, count);
    if (n != count)
        perror("/dev/kmem read failed");
    else
        printf("/dev/kmem read buf = %ld\n", *(unsigned long *)buf);

    close(fd);
    return n;
}

/* read from physical memory */
int read_mem(off_t offset, void* buf, size_t count)
{
    int fd;
    int n;
    int page_size;
    void *map_base;
    unsigned long value;

    printf("/dev/mem: the offset is %lx\n", offset);

    fd = open("/dev/mem", O_RDONLY);
    if (fd < 0)
    {
        perror("open /dev/mem failed");
        return -1;
    }

    if(1){
        page_size = getpagesize();
        printf("the page size = %d\n", page_size);
        map_base = mmap(0,page_size,PROT_READ,MAP_SHARED,fd,offset);
        if (map_base == MAP_FAILED){
            perror("mmap");
            exit(1);
        }
        value = LONG(map_base);
        printf("/dev/mem: the value is %ld\n", value);
        buf = (unsigned long *)map_base;
    }

    if(0){
        lseek(fd, offset, SEEK_SET);
        n = read(fd, buf, count);
        if (n != count)
            perror("/dev/mem read failed");
        else
            printf("/dev/mem read buf = %ld\n", *(unsigned long *)buf);
    }

    close(fd);
    return n;
}

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

#include <mach/mach.h>

// http://www.newosxbook.com/src.jl?tree=listings&file=12-1-vmmap.c
unsigned char *
readProcessMemory (int pid, mach_vm_address_t addr, mach_msg_type_number_t *size)
{
    // Helper function to read process memory (a la Win32 API of same name)
    // To make it easier for inclusion elsewhere, it takes a pid, and
    // does the task_for_pid by itself. Given that iOS invalidates task ports
    // after use, it's actually a good idea, since we'd need to reget anyway

    task_t	t;
    task_for_pid(mach_task_self(),pid, &t);
    mach_msg_type_number_t  dataCnt = size;
    vm_offset_t readMem;

    // Use vm_read, rather than mach_vm_read, since the latter is different
    // in iOS.

    kern_return_t kr = vm_read(t,        // vm_map_t target_task,
                               addr,     // mach_vm_address_t address,
                               *size,     // mach_vm_size_t size
                               &readMem,     //vm_offset_t *data,
                               size);     // mach_msg_type_number_t *dataCnt

    if (kr) {
        // DANG..
        fprintf (stderr, "Unable to read target task's memory @%p - kr 0x%x\n" , addr, kr);
        return NULL;
    }

    return ( (unsigned char *) readMem);

}

void write_process_memory(int pid, mach_vm_address_t addr, const char* buf, int buf_size) {
    task_t	t;
    task_for_pid(mach_task_self(), pid, &t);
    mach_msg_type_number_t  dataCnt = buf_size;
    vm_offset_t readMem;

    kern_return_t kr = vm_write(
        t,
        addr,
        (vm_offset_t)buf,
        buf_size
    );

    if (kr) {
        fprintf(stderr, "Unable to write target task's memory @%p - kr 0x%x\n" , addr, kr);
    }
    else {
        printf("Write succeeded\n");
    }
}

int main(int argc, char **argv) {
    mach_port_t kernel_task = 0;
    int ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    printf("task_for_pid_0 = %d\n", ret);

    int size = 64;
    mach_msg_type_number_t  dataCnt = size;
    int addr = 0x803c100a;
    char new_data[] = {0x00, 0x20, 0x70, 0x47};
    int byte_count = sizeof(new_data) / sizeof(new_data[0]);

    printf("Replacing %d bytes...\n", byte_count);
    unsigned char* readData = readProcessMemory(0, addr, &dataCnt);
    printf("Original: \n");
    hexdump(readData, size);

    write_process_memory(0, addr, &new_data, byte_count);

    char* readAgain = readProcessMemory(0, addr, &dataCnt);
    printf("Read again: \n");
    hexdump(readAgain, size);

    /*
    printf("Patching MAC flags...\n");
    const char zero_u32[4] = {0, 0, 0, 0};
    write_process_memory(0, 0x8025ef80, &zero_u32, 4);
    write_process_memory(0, 0x8025eff8, &zero_u32, 4);
    write_process_memory(0, 0x8025f020, &zero_u32, 4);
    write_process_memory(0, 0x8025f048, &zero_u32, 4);
    write_process_memory(0, 0x8025f070, &zero_u32, 4);
    write_process_memory(0, 0x8025f098, &zero_u32, 4);
    write_process_memory(0, 0x8025f0c0, &zero_u32, 4);
    write_process_memory(0, 0x8025f0e8, &zero_u32, 4);
    write_process_memory(0, 0x8025f110, &zero_u32, 4);
    write_process_memory(0, 0x8025f138, &zero_u32, 4);
    write_process_memory(0, 0x8025f160, &zero_u32, 4);
    write_process_memory(0, 0x8025f188, &zero_u32, 4);
    printf("Done patching MAC flags\n");
     */

    return 0;
    /*
    int kmem_fd = open("/dev/kmem", O_RDONLY);
    printf("Got fd %d\n", kmem_fd);
    lseek(kmem_fd, (off_t)ptr, SEEK_SET);
    printf("Seek worked!\n");
    char* buf = malloc(1024);
    int a = read(kmem_fd, buf, 512);
    printf("read returned %d\n", a);
    printf("errno = %d\n", errno);
    hexdump(buf, 128);
     */
    FILE* f = fopen("/dev/mem", "rb");
    printf("f %p\n", f);
    void* ptr = (void*)0x0;
    fseek(f, (off_t)ptr, SEEK_SET);
    char* buf = malloc(1024);
    int a = fread(buf, 1, 512, f);
    printf("fread returned %d\n", a);
    printf("errno = %d\n", errno);
    hexdump(buf, 128);
    /*
    char* kmem = (unsigned char *)mmap(0, getpagesize(), PROT_READ, MAP_SHARED, kmem_fd, 0x0);
    printf("got kmem %p\n", kmem);
    hexdump(kmem, 512);
     */

    return 0;
}
