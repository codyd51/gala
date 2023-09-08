//
//  payload2.c
//  jailbreak
//
//  Created by Phillip Tennen on 10/07/2023.
//

#include <stdint.h>
#include <stddef.h>

#define printf_addr 0x21ef0

//int printf(char* msg, ...);

void hexdump(const void* data, size_t size) {
    int (*printf)() = (void*)printf_addr;

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

// PT: Be very careful to not declare/use any global data, as those binary sections are stripped
void c_entry_point(int r0, int r1, int r2, int r3, int r4, int r5, int r6, int r7, int r8) {
    hexdump(r0, 1024);
}

