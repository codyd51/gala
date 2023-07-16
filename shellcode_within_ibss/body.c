//
//  payload2.c
//  jailbreak
//
//  Created by Phillip Tennen on 10/07/2023.
//

#include <stdint.h>
#include <stddef.h>

#define dprintf_addr 0x84016fc9 // + 1 to go to THUMB


// PT: Be very careful to not declare/use any global data, as those binary sections are stripped
void c_entry_point(char* msg) {
    void (*dprintf)(char* msg, ...) = (void*)dprintf_addr;
    dprintf(msg);
}
