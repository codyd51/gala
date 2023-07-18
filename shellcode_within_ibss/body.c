//
//  payload2.c
//  jailbreak
//
//  Created by Phillip Tennen on 10/07/2023.
//

#include <stdint.h>
#include <stddef.h>

#define dprintf_addr 0x84016fc9 // + 1 to go to THUMB
#define pinot_quiesce_addr 0x84006195 // + 1 to go to THUMB


// PT: Be very careful to not declare/use any global data, as those binary sections are stripped
void c_entry_point(char* msg, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8, int arg9, int arg10) {
    void (*dprintf)(char* msg, ...) = (void*)dprintf_addr;
    //void (*pinot_quiesce)(void) = (void*)pinot_quiesce_addr;
    dprintf(msg, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
    //pinot_quiesce();
}
