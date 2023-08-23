#include <stdint.h>
#include <string.h>
#include <errno.h>

int unmount(const char* path, int flags);
int printf(const char* fmt, ...);

int main(int argc, const char** argv) {
	const char* path = argv[1];
	printf("Unmounting %s...\n", path);
    int8_t ret = unmount(path, 0);
    if (ret == -1) {
        printf("Unmount failed! errnno = %s\n", strerror(errno));
    }
    return ret;
}
