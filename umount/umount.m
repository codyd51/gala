#include <stdint.h>

int unmount(const char* path, int flags);
int printf(const char* fmt, ...);

int main(int argc, const char** argv) {
	const char* path = argv[1];
	printf("Unmounting %s...\n", path);
	return unmount(path, 0);
}
