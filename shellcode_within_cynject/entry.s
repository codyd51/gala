.text

.pool
.set printf, 0x0000b838

.code 16
_start: .global _start
    push {lr}
    @ Preserve registers
    push {r0-r11}

    mov r0, #0
    adr r1, intro
    @mov r2, lr
    @sub r2, r2, #5
    ldr r11, =printf
    blx r11

    pop {r0-r11}

    pop {pc}

    push {r6}
    push {r7}
    push {r8}

    push {r3}
    push {r4}
    push {r5}

    push {r0}
    push {r1}
    push {r2}

    mov r0, #2
    adr r1, intro
    mov r2, lr
    sub r2, r2, #5
    ldr r11, =printf
    blx r11

    pop {r4}
    pop {r3}
    pop {r2}

    adr r1, msg1
    blx r11

    pop {r4}
    pop {r3}
    pop {r2}

    adr r1, msg1
    blx r11

    pop {r4}
    pop {r3}
    pop {r2}

    adr r1, msg1
    blx r11

    @ Restore registers
    pop {r0-r11}

    pop {pc}

.align 2
intro:
.asciz "\n*** Reg-dump @ 0x%08x\n\0"

msg1:
.asciz "0x%08x\n0x%08x\n0x%08x\n\0"
