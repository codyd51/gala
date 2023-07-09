//
//  payload_body.c
//  jailbreak
//
//  Created by Phillip Tennen on 08/07/2023.
//

#include <stdint.h>
#include <stddef.h>

/*.set    RET_ADDR,            0x7ef
 .set    loadaddr,            0x84000000
 .set    maxsize,            0x24000
 .set    dumpaddr,            0x0
 .set    dumpto,                0x84000000
 .set    dumpsize,            0x10000
*/

#define DUMP_TO 0x84000000
#define DUMP_FROM 0x8402c160
#define DUMP_SIZE 0x10000

void memcpy(char* dest, char* source, int size) {
    for (int i = 0; i < size; i++) {
        *dest = *source;
        dest += 1;
        source += 1;
    }
}


void c_entry_point(char* pwned_serial, int pwned_serial_len) {
    memcpy(DUMP_TO, DUMP_FROM, DUMP_SIZE);
    unsigned int *p = 0;
    
    // Try to draw to the framebuffer
    for(p = (unsigned int*)0x5F700000; p < (unsigned int*)(0x5F700000 + (640 * 960 * 4)); p++) {
        *p = 0xff0088;
    }
    
    // Overwrite the serial number
    char* serial = (char*)0x8402e0e0;
    memcpy(serial, pwned_serial, pwned_serial_len);
}

/*
 entry_point:
     LDR    R0,    =dumpto
     LDR    R1,    =dumpaddr
     LDR    R2,    =dumpsize
     BL    memcpy

     LDR    R0,    =loadaddr
     LDR    R1,    =maxsize
     MOV    R2,    #0
     LDR    R3,    =RET_ADDR
     BLX    R3
 @-----------------------------------------------------
 memcpy:

 _memcpy_loop:
         LDRB     R3,     [R1]
         STRB     R3,     [R0]
         ADD     R0,     #1
         ADD     R1,     #1
         SUB     R2,     #1
         CMP     R2,     #0
         BNE     _memcpy_loop

         BX      LR

 */
