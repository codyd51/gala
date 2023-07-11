//
//  payload2.c
//  jailbreak
//
//  Created by Phillip Tennen on 10/07/2023.
//

#include <stdint.h>
#include <stddef.h>

void memcpy(char* dest, char* source, int size) {
    for (int i = 0; i < size; i++) {
        *dest = *source;
        dest += 1;
        source += 1;
    }
}

#define get_dfu_image_addr 0x4c85 // + 1 to go to THUMB

// PT: Be very careful to not declare/use any global data, as those binary sections are stripped
void c_entry_point(char* pwned_serial, int pwned_serial_len) {
    //char* serial = (char*)0x8402e0e0;
    //memcpy(serial, pwned_serial, pwned_serial_len);
}

