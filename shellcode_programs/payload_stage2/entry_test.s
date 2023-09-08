//
//  payload2_tiny.s
//  jailbreak
//
//  Created by Phillip Tennen on 11/07/2023.
//
/*
 .code 16
 .text
 
 .extern _c_entry_point
 
 bx lr
 
 adr r0, pwned_serial
 mov r1, pwned_serial_len
 
 push {lr}
 bl _c_entry_point
 pop {lr}
 
 bx lr
 
 .align 2
 pwned_serial:
 .asciz "[Overwritten serial number!]"
 @pwned_serial_len:
 @ .equ . - pwned_serial
 pwned_serial_len = . - pwned_serial
 */
 //.code 16
 .text

//bx lr
pop {pc}
