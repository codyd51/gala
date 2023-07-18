.text

.extern _c_entry_point

.pool
.set dprintf, 0x84016fc9

.code 16
_start: .global _start
    push {lr}

    @ Preserve registers
    push {r0-r11}

    @mov r0, #0
    @mov r1, #1
    @mov r2, #2
    @mov r3, #3
    @mov r4, #4
    @mov r5, #5
    @mov r6, #6
    @mov r7, #7
    @mov r8, #8
    @mov r9, #9
    @mov r10, #10

    push {r6}
    push {r7}
    push {r8}

    push {r3}
    push {r4}
    push {r5}

    push {r0}
    push {r1}
    push {r2}

    adr r0, intro
    movw r11, #0x6fc9
    movt r11, #0x8401
    blx r11

    pop {r3}
    pop {r2}
    pop {r1}

    adr r0, msg1
    blx r11

    pop {r3}
    pop {r2}
    pop {r1}

    adr r0, msg1
    blx r11

    pop {r3}
    pop {r2}
    pop {r1}

    adr r0, msg1
    blx r11

    @ Restore registers
    pop {r0-r11}

    pop {pc}

.align 2
msg:
.asciz "test\n\0"
@.asciz "image_load_memory(%08x, %08x, %08x, %08x, %08x, %08x, %08x)\n\0"
@.asciz "We get to image3_load_copyobject(r0=0x%x, r1=?, r2=0x%08x, r3=0x%08x, r4=0x%08x, r5=0x%08x)\n\0"
@.asciz "Inspect r0=0x%x, r1=?, r2=0x%08x, r3=0x%08x, r4=0x%08x, r5=0x%08x\n\0"
@.asciz "PWNED jumping into image at 0x%08x!.\n\0"
@.asciz "The above block doesn't jump!\n\0"
@.asciz "r0 = 0x%08x\nr1 = ?\nr2 = 0x%08x\nr3 = 0x%08x\nr4 = 0x%08x\nr5 = 0x%08x\nr6 = 0x%08x\n\0"
@msg_len = . - msg

intro:
.asciz "\nRegister dump\n\0"

msg1:
@.asciz "r0 = 0x%08x\nr1 = 0x%08x\nr2 = 0x%08x\nr3 = 0x%08x\nr4 = 0x%08x\nr5 = 0x%08x\nr6 = 0x%08x\nr7 = 0x%08x\nr8 = 0x%08x\nr9 = 0x%08x\nr10 = 0x%08x\n\0"
.asciz "0x%08x\n0x%08x\n0x%08x\n\0"
@msg2:
@.asciz "msg2 r2 = 0x%08x\nmsg2 r3 = 0x%08x\nmsg2 r4 = 0x%08x\nmsg2 r5 = 0x%08x\nmsg2 r6 = 0x%08x\n\n\0"
