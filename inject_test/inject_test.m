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

/*
 *	Kernel-related ports; how a task/thread controls itself
 */

extern mach_port_t mach_host_self(void);
extern mach_port_t mach_thread_self(void);
extern kern_return_t host_page_size(host_t, vm_size_t *);

extern mach_port_t      mach_task_self_;
//#define mach_task_self() mach_task_self_
#define current_task()  mach_task_self()

int main2(int argc, char **argv) {
    mach_port_t task;
    int ret = task_for_pid(mach_task_self(), 1, &task);
    printf("task_for_pid = %d\n", ret);

    //vm_size_t size(depth + Stack_);
    vm_size_t size = 4096;
    vm_address_t stack;
    ret = vm_allocate(task, &stack, size, true);
    printf("vm_allocate = %d\n", ret);
    printf("stack 0x%08x\n", stack);

    char* data = malloc(1024);
    memset(data, 'A', 1024);
    ret = vm_write(task, stack, (vm_offset_t)data, 1024);
    printf("vm_write = %d\n", ret);

    thread_act_t thread;
    ret = thread_create(task, &thread);
    printf("thread_create = %d\n", ret);
    printf("thread = 0x%08x\n", thread);

    vm_address_t stack2;
    ret = vm_allocate(task, &stack2, 1024, true);
    printf("vm_allocate = %d\n", ret);
    ret = vm_write(task, stack, (vm_offset_t)data, 1024);
    printf("vm_write = %d\n", ret);
    ret = vm_protect(task, stack, 4096, false, VM_PROT_READ | VM_PROT_EXECUTE);
    printf("vm_protect = %d\n", ret);

    thread_state_flavor_t flavor;
    arm_thread_state_t state;
    mach_msg_type_number_t read = 1024;
    ret = thread_get_state(thread, flavor, &state, &read);
    printf("thread_get_state = %d\n", ret);

    while (1) {
        printf("sleeping...\n");
        sleep(1);
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>

bool MSHookProcess(int, const char*);

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <pid> <dylib>\n", argv[0]);
        return 1;
    }

    pid_t pid = strtoul(argv[1], NULL, 10);
    const char *library = argv[2];

    task_t task;
    int ret = task_for_pid(mach_task_self(), pid, &task);
    printf("task_for_pid returned %d\n", ret);
    /*
    task_info_t* info;
    mach_msg_type_number_t count;
    ret = task_info(task, TASK_DYLD_INFO, (task_info_t)info, &count);
     */
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    ret = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    printf("task_info ret = %d\n", ret);
    printf("task_info 0x%08x count %d\n", dyld_info, count);
    printf("field0 0x%08x field1 0x%08x\n", dyld_info.all_image_info_addr, dyld_info.all_image_info_size);

    /*
    if (!MSHookProcess(pid, library)) {
        fprintf(stderr, "MSHookProcess() failed.\n");
        return 1;
    }
     */
    /*
    #define TASK_DYLD_INFO			17	/* This is experimental. */

    /*        struct task_dyld_info {
            mach_vm_address_t	all_image_info_addr;
            mach_vm_size_t		all_image_info_size;
        };
        typedef struct task_dyld_info	task_dyld_info_data_t;
        typedef struct task_dyld_info	*task_dyld_info_t;
    #define TASK_DYLD_INFO_COUNT	\
    		(sizeof(task_dyld_info_data_t) / sizeof(natural_t))
    TASK_DYLD_INFO
    */

    return 0;
}

